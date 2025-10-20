#!/usr/bin/env python3
"""Self-contained portable ping monitoring web application."""
import base64
import datetime as dt
import hashlib
import html
import json
import os
import platform
import secrets
import threading
import time
import urllib.parse
import uuid
from collections import deque
from http import cookies
from wsgiref.simple_server import make_server

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data.json")
LOGS_DIR = os.path.join(BASE_DIR, "LOGS")

os.makedirs(LOGS_DIR, exist_ok=True)
PING_INTERVAL = 2  # seconds
SESSION_TTL = 3600  # seconds


def _now() -> dt.datetime:
    return dt.datetime.utcnow()


def _format_ts(ts: float | None) -> str:
    if not ts:
        return "–"
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return digest, salt


class DataStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.data = {
            "password_hash": None,
            "salt": None,
            "hosts": [],
        }
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                try:
                    loaded = json.load(fh)
                    self.data.update(loaded)
                except json.JSONDecodeError:
                    pass
        if not self.data.get("password_hash"):
            digest, salt = _hash_password("admin")
            self.data["password_hash"] = digest
            self.data["salt"] = salt
            self._save()
        for host in self.data.get("hosts", []):
            host_id = host.get("id")
            if host_id:
                self._ensure_log_file(host_id)

    @staticmethod
    def _log_file_path(host_id: str) -> str:
        return os.path.join(LOGS_DIR, f"{host_id}.log")

    def _ensure_log_file(self, host_id: str) -> None:
        path = self._log_file_path(host_id)
        if not os.path.exists(path):
            with open(path, "a", encoding="utf-8"):
                pass

    def _append_host_log(self, host_id: str, timestamp: float, status: str) -> None:
        iso = (
            dt.datetime.fromtimestamp(timestamp, dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        entry = {"ts": timestamp, "timestamp": iso, "status": status}
        path = self._log_file_path(host_id)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)

    def verify_password(self, password: str) -> bool:
        digest, _ = _hash_password(password, self.data["salt"])
        return secrets.compare_digest(digest, self.data["password_hash"])

    def update_password(self, new_password: str) -> None:
        digest, salt = _hash_password(new_password)
        with self.lock:
            self.data["password_hash"] = digest
            self.data["salt"] = salt
            self._save()

    def get_hosts(self) -> list[dict]:
        with self.lock:
            return [host.copy() for host in self.data["hosts"]]

    def add_host(self, computer: str, group: str, ip: str) -> None:
        host = {
            "id": uuid.uuid4().hex,
            "computer": computer,
            "group": group,
            "ip": ip,
            "status": "unknown",
            "last_update": None,
        }
        with self.lock:
            self.data["hosts"].append(host)
            self._ensure_log_file(host["id"])
            self._save()

    def update_host_status(self, host_id: str, status: str) -> None:
        timestamp = time.time()
        with self.lock:
            for host in self.data["hosts"]:
                if host["id"] == host_id:
                    host["status"] = status
                    host["last_update"] = timestamp
                    self._append_host_log(host_id, timestamp, status)
                    break
            self._save()

    def get_host(self, host_id: str) -> dict | None:
        with self.lock:
            for host in self.data["hosts"]:
                if host["id"] == host_id:
                    return host.copy()
        return None

    def get_host_log(self, host_id: str, limit: int = 1000) -> list[dict]:
        path = self._log_file_path(host_id)
        if not os.path.exists(path):
            return []
        entries: deque[dict] = deque(maxlen=limit)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "ts" not in entry and "timestamp" in entry:
                    try:
                        dt_obj = dt.datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
                        entry["ts"] = dt_obj.timestamp()
                    except ValueError:
                        entry["ts"] = 0.0
                if "timestamp" not in entry and "ts" in entry:
                    iso = dt.datetime.utcfromtimestamp(float(entry["ts"])).replace(microsecond=0).isoformat() + "Z"
                    entry["timestamp"] = iso
                entries.append(entry)
        return list(entries)


class SessionStore:
    def __init__(self):
        self.sessions: dict[str, float] = {}
        self.lock = threading.Lock()

    def create(self) -> str:
        sid = secrets.token_hex(16)
        with self.lock:
            self.sessions[sid] = time.time() + SESSION_TTL
        return sid

    def validate(self, sid: str | None) -> bool:
        if not sid:
            return False
        with self.lock:
            expiry = self.sessions.get(sid)
            if expiry is None:
                return False
            if expiry < time.time():
                del self.sessions[sid]
                return False
            self.sessions[sid] = time.time() + SESSION_TTL
            return True

    def destroy(self, sid: str | None) -> None:
        if not sid:
            return
        with self.lock:
            self.sessions.pop(sid, None)


class PingWorker:
    def __init__(self, store: DataStore):
        self.store = store
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join()

    def _run(self) -> None:
        while not self.stop_event.is_set():
            hosts = self.store.get_hosts()
            for host in hosts:
                status = self._ping(host["ip"])
                self.store.update_host_status(host["id"], status)
                if self.stop_event.wait(PING_INTERVAL):
                    return
            if not hosts:
                if self.stop_event.wait(PING_INTERVAL):
                    return

    @staticmethod
    def _ping(ip: str) -> str:
        from subprocess import DEVNULL, CalledProcessError, run

        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        try:
            result = run(cmd, check=True, stdout=DEVNULL, stderr=DEVNULL)
            return "online" if result.returncode == 0 else "offline"
        except (FileNotFoundError, CalledProcessError):
            return "offline"


def parse_post(environ: dict) -> dict[str, str]:
    try:
        size = int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        size = 0
    body = environ["wsgi.input"].read(size) if size else b""
    return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}


def redirect(location: str):
    body = b""
    headers = [
        ("Location", location),
        ("Content-Type", "text/html; charset=utf-8"),
        ("Content-Length", "0"),
    ]
    return "302 Found", headers, body


def render_template(title: str, content: str, user_authenticated: bool = True) -> bytes:
    html_doc = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    nav a {{ margin-right: 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
    th button {{ background: none; border: none; color: #06c; cursor: pointer; }}
    form.inline {{ display: inline; }}
    .status-online {{ color: green; font-weight: bold; }}
    .status-offline {{ color: red; font-weight: bold; }}
    .status-unknown {{ color: #666; font-weight: bold; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .link-button {{ background: none; border: none; color: #06c; text-decoration: underline; cursor: pointer; padding: 0; font: inherit; }}
    .link-button:focus {{ outline: 2px solid #06c; outline-offset: 2px; }}
    .modal {{ display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); align-items: center; justify-content: center; z-index: 1000; padding: 1rem; }}
    .modal.visible {{ display: flex; }}
    .modal-content {{ background: #fff; border-radius: 6px; max-width: 960px; width: 100%; padding: 1.5rem; position: relative; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); }}
    .modal-close {{ position: absolute; top: 0.5rem; right: 0.5rem; background: none; border: none; font-size: 1.5rem; cursor: pointer; }}
    .modal-close:hover {{ color: #c00; }}
    #host-modal-chart {{ width: 100%; max-width: 100%; border: 1px solid #ddd; margin-top: 1rem; background: #fefefe; }}
    .modal-status {{ margin-top: 1rem; font-weight: bold; }}
    .modal-events {{ list-style: none; padding-left: 0; max-height: 200px; overflow-y: auto; margin-top: 1rem; }}
    .modal-events li {{ padding: 0.25rem 0; border-bottom: 1px solid #eee; }}
    .modal-legend {{ margin-top: 0.5rem; display: flex; gap: 1rem; flex-wrap: wrap; }}
    .modal-legend span {{ display: inline-flex; align-items: center; gap: 0.3rem; }}
    .legend-swatch {{ width: 12px; height: 12px; border-radius: 2px; display: inline-block; }}
  </style>
</head>
<body>
  <div class=\"container\">
    <h1>Ping Monitor</h1>
    {"<nav><a href='/'>Dashboard</a><a href='/settings'>Settings</a><a href='/logout'>Logout</a></nav>" if user_authenticated else ""}
    {content}
  </div>
</body>
</html>
"""
    return html_doc.encode("utf-8")


def html_escape(value: str) -> str:
    return html.escape(value, quote=True)


def filter_and_sort_hosts(
    store: DataStore, query: dict[str, str]
) -> tuple[list[dict], str, str, str, str]:
    group_filter = query.get("group_filter", "").strip()
    status_filter = query.get("status_filter", "").strip()
    sort_column = query.get("sort", "computer")
    sort_dir = query.get("dir", "asc")

    hosts = store.get_hosts()
    if group_filter:
        hosts = [h for h in hosts if h.get("group", "") == group_filter]
    if status_filter:
        hosts = [h for h in hosts if h.get("status", "") == status_filter]

    key_func = {
        "computer": lambda h: h.get("computer", "").lower(),
        "group": lambda h: h.get("group", "").lower(),
        "ip": lambda h: h.get("ip", ""),
        "status": lambda h: h.get("status", ""),
    }.get(sort_column, lambda h: h.get("computer", ""))

    reverse = sort_dir == "desc"
    hosts.sort(key=key_func, reverse=reverse)

    return hosts, group_filter, status_filter, sort_column, sort_dir


def dashboard_page(store: DataStore, query: dict[str, str]) -> bytes:
    hosts, group_filter, status_filter, sort_column, sort_dir = filter_and_sort_hosts(
        store, query
    )

    def sort_link(column: str, label: str) -> str:
        direction = "desc" if (sort_column == column and sort_dir == "asc") else "asc"
        params = query.copy()
        params.update({"sort": column, "dir": direction})
        href = "/?" + urllib.parse.urlencode(params)
        arrow = "" if sort_column != column else ("▲" if sort_dir == "asc" else "▼")
        return f"<a href='{href}'>{html_escape(label)} {arrow}</a>"

    rows = []
    for host in hosts:
        status = host.get("status", "unknown")
        css = f"status-{status}"
        host_id = html_escape(host.get("id", ""))
        computer_name = html_escape(host.get("computer", "")) or "Unnamed"
        row_html = "".join(
            [
                "<tr>",
                (
                    "<td>"
                    f"<button type='button' class='link-button' data-host-button data-host-id='{host_id}' data-host-name='{computer_name}'>"
                    f"{computer_name}"
                    "</button>"
                    "</td>"
                ),
                f"<td>{html_escape(host.get('group', ''))}</td>",
                f"<td>{html_escape(host.get('ip', ''))}</td>",
                f"<td class='{css}'>{html_escape(status)}</td>",
                f"<td>{html_escape(_format_ts(host.get('last_update')))}</td>",
                "</tr>",
            ]
        )
        rows.append(row_html)
    group_options = sorted({h.get("group", "") for h in store.get_hosts() if h.get("group")})
    status_options = ["online", "offline", "unknown"]

    filters_html = """
    <form method=\"get\">
      <label>Group:
        <select name=\"group_filter\">
          <option value=\"\">All</option>
          {group_options}
        </select>
      </label>
      <label>Status:
        <select name=\"status_filter\">
          <option value=\"\">All</option>
          {status_options}
        </select>
      </label>
      <button type=\"submit\">Apply</button>
    </form>
    """.format(
        group_options="".join(
            f"<option value='{html_escape(opt)}' {'selected' if opt == group_filter else ''}>{html_escape(opt)}</option>"
            for opt in group_options
        ),
        status_options="".join(
            f"<option value='{opt}' {'selected' if opt == status_filter else ''}>{opt.title()}</option>"
            for opt in status_options
        ),
    )

    add_form = """
    <h2>Add computer</h2>
    <form method=\"post\" action=\"/add\">
      <label>Computer name <input type=\"text\" name=\"computer\" required></label>
      <label>Group <input type=\"text\" name=\"group\"></label>
      <label>IP address <input type=\"text\" name=\"ip\" required></label>
      <button type=\"submit\">Add</button>
    </form>
    """

    table_html = """
    <h2>Monitored computers</h2>
    {filters}
    <table>
      <thead>
        <tr>
          <th>{computer_sort}</th>
          <th>{group_sort}</th>
          <th>{ip_sort}</th>
          <th>{status_sort}</th>
          <th>Last update</th>
        </tr>
      </thead>
      <tbody data-hosts-table>
        {rows}
      </tbody>
    </table>
    """.format(
        filters=filters_html,
        computer_sort=sort_link("computer", "Computer"),
        group_sort=sort_link("group", "Group"),
        ip_sort=sort_link("ip", "IP"),
        status_sort=sort_link("status", "Status"),
        rows="".join(rows) if rows else "<tr><td colspan='5'>No computers added yet.</td></tr>",
    )

    modal_html = """
    <div id=\"host-modal\" class=\"modal\" data-host-modal aria-hidden=\"true\">
      <div class=\"modal-content\">
        <button type=\"button\" class=\"modal-close\" data-modal-close aria-label=\"Close\">&times;</button>
        <h3 id=\"host-modal-title\"></h3>
        <div class=\"modal-legend\">
          <span><span class=\"legend-swatch\" style=\"background:#2ecc71;\"></span>Online</span>
          <span><span class=\"legend-swatch\" style=\"background:#e74c3c;\"></span>Offline</span>
          <span><span class=\"legend-swatch\" style=\"background:#95a5a6;\"></span>Unknown</span>
        </div>
        <canvas id=\"host-modal-chart\" width=\"900\" height=\"260\"></canvas>
        <p id=\"host-modal-status\" class=\"modal-status\"></p>
        <ul id=\"host-modal-events\" class=\"modal-events\"></ul>
      </div>
    </div>
    """

    auto_refresh_script = """
    <script>
    (function() {
      const tableBody = document.querySelector('[data-hosts-table]');
      const modal = document.querySelector('[data-host-modal]');
      const modalTitle = document.getElementById('host-modal-title');
      const modalStatus = document.getElementById('host-modal-status');
      const eventsList = document.getElementById('host-modal-events');
      const modalClose = document.querySelector('[data-modal-close]');
      const canvas = document.getElementById('host-modal-chart');
      const ctx = canvas ? canvas.getContext('2d') : null;
      if (!tableBody) {
        return;
      }

      const statusClass = (status) => {
        switch ((status || '').toLowerCase()) {
          case 'online':
            return 'status-online';
          case 'offline':
            return 'status-offline';
          default:
            return 'status-unknown';
        }
      };

      const closeModal = () => {
        if (!modal) {
          return;
        }
        modal.classList.remove('visible');
        modal.setAttribute('aria-hidden', 'true');
      };

      if (modalClose) {
        modalClose.addEventListener('click', closeModal);
      }
      if (modal) {
        modal.addEventListener('click', (event) => {
          if (event.target === modal) {
            closeModal();
          }
        });
        document.addEventListener('keydown', (event) => {
          if (event.key === 'Escape' && modal.classList.contains('visible')) {
            closeModal();
          }
        });
      }

      const drawHostChart = (entries) => {
        if (!ctx || !canvas) {
          return;
        }
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#f8f8f8';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        const padding = 40;
        const chartWidth = canvas.width - padding * 2;
        const chartHeight = canvas.height - padding * 2;

        ctx.strokeStyle = '#333';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(padding, padding);
        ctx.lineTo(padding, canvas.height - padding);
        ctx.lineTo(canvas.width - padding, canvas.height - padding);
        ctx.stroke();

        if (!entries.length) {
          ctx.fillStyle = '#333';
          ctx.font = '14px Arial';
          ctx.textAlign = 'center';
          ctx.fillText('No ping data to display', canvas.width / 2, canvas.height / 2);
          return;
        }

        const sorted = entries.slice().sort((a, b) => (a.ts || 0) - (b.ts || 0));
        const minTime = sorted[0].ts || 0;
        const maxTime = sorted[sorted.length - 1].ts || minTime;
        const duration = Math.max(maxTime - minTime, 1);
        const colors = { online: '#2ecc71', offline: '#e74c3c', unknown: '#95a5a6' };

        sorted.forEach((entry, index) => {
          const status = (entry.status || 'unknown').toLowerCase();
          const color = colors[status] || '#999';
          const start = ((entry.ts || minTime) - minTime) / duration;
          const endValue = index < sorted.length - 1 ? ((sorted[index + 1].ts || maxTime) - minTime) / duration : 1;
          const x1 = padding + start * chartWidth;
          const x2 = padding + endValue * chartWidth;
          ctx.fillStyle = color;
          ctx.fillRect(x1, padding, Math.max(x2 - x1, 2), chartHeight);
        });

        ctx.strokeStyle = 'rgba(255, 255, 255, 0.6)';
        ctx.beginPath();
        ctx.moveTo(padding, padding + chartHeight / 2);
        ctx.lineTo(canvas.width - padding, padding + chartHeight / 2);
        ctx.stroke();

        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        const labelTimes = [minTime, minTime + duration / 2, maxTime];
        labelTimes.forEach((value) => {
          const x = padding + ((value - minTime) / duration) * chartWidth;
          const date = new Date(value * 1000);
          ctx.fillText(date.toLocaleTimeString(), x, canvas.height - padding + 20);
        });

        const offlineTransitions = [];
        for (let i = 1; i < sorted.length; i += 1) {
          const previousStatus = (sorted[i - 1].status || 'unknown').toLowerCase();
          const currentStatus = (sorted[i].status || 'unknown').toLowerCase();
          if (previousStatus === 'online' && currentStatus === 'offline') {
            offlineTransitions.push(sorted[i]);
          }
        }

        if (offlineTransitions.length) {
          ctx.save();
          ctx.strokeStyle = '#c0392b';
          ctx.fillStyle = '#c0392b';
          ctx.font = '12px Arial';
          ctx.textAlign = 'center';
          offlineTransitions.forEach((entry) => {
            const ts = entry.ts || minTime;
            const ratio = ((ts - minTime) / duration);
            const x = padding + ratio * chartWidth;
            ctx.beginPath();
            ctx.moveTo(x, padding);
            ctx.lineTo(x, canvas.height - padding);
            ctx.stroke();
            const date = new Date(ts * 1000);
            const label = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            ctx.fillText(label, x, padding - 10);
          });
          ctx.restore();
        }
      };

      const renderEventsList = (entries) => {
        if (!eventsList) {
          return;
        }
        eventsList.innerHTML = '';
        if (!entries.length) {
          const li = document.createElement('li');
          li.textContent = 'No ping data recorded yet.';
          eventsList.appendChild(li);
          return;
        }
        const recent = entries.slice(-50).reverse();
        recent.forEach((entry) => {
          const li = document.createElement('li');
          const statusText = (entry.status || 'unknown').toUpperCase();
          const ts = entry.ts || (entry.timestamp ? Date.parse(entry.timestamp) / 1000 : 0);
          const date = new Date(ts * 1000);
          li.textContent = `${statusText} — ${date.toLocaleString()}`;
          eventsList.appendChild(li);
        });
      };

      const openHostModal = (hostId, hostName) => {
        if (!modal) {
          return;
        }
        modal.classList.add('visible');
        modal.setAttribute('aria-hidden', 'false');
        if (modalTitle) {
          modalTitle.textContent = hostName || 'Computer';
        }
        if (modalStatus) {
          modalStatus.textContent = 'Loading ping history...';
        }
        renderEventsList([]);
        drawHostChart([]);
        const url = `/api/host_log?host_id=${encodeURIComponent(hostId)}`;
        fetch(url, { headers: { 'Accept': 'application/json' } })
          .then((response) => {
            if (!response.ok) {
              throw new Error('Network error');
            }
            return response.json();
          })
          .then((data) => {
            const entries = data && Array.isArray(data.entries) ? data.entries : [];
            drawHostChart(entries);
            renderEventsList(entries);
            if (modalStatus) {
              if (!entries.length) {
                modalStatus.textContent = 'No ping data recorded yet.';
              } else {
                const last = entries[entries.length - 1];
                const ts = last.ts || (last.timestamp ? Date.parse(last.timestamp) / 1000 : 0);
                const date = new Date(ts * 1000);
                const statusText = (last.status || 'unknown').toUpperCase();
                modalStatus.textContent = `Last ping: ${statusText} at ${date.toLocaleString()}`;
              }
            }
            if (data && data.host && modalTitle && data.host.computer) {
              modalTitle.textContent = data.host.computer;
            }
          })
          .catch(() => {
            if (modalStatus) {
              modalStatus.textContent = 'Unable to load ping history.';
            }
          });
      };

      const attachHostHandlers = () => {
        tableBody.querySelectorAll('[data-host-button]').forEach((button) => {
          if (button.dataset.bound === '1') {
            return;
          }
          button.dataset.bound = '1';
          button.addEventListener('click', () => {
            const hostId = button.getAttribute('data-host-id') || '';
            const hostName = button.getAttribute('data-host-name') || button.textContent || 'Computer';
            openHostModal(hostId, hostName);
          });
        });
      };

      const renderHosts = (hosts) => {
        tableBody.innerHTML = '';
        if (!hosts.length) {
          const row = document.createElement('tr');
          const cell = document.createElement('td');
          cell.colSpan = 5;
          cell.textContent = 'No computers added yet.';
          row.appendChild(cell);
          tableBody.appendChild(row);
          return;
        }

        hosts.forEach((host) => {
          const row = document.createElement('tr');

          const computerCell = document.createElement('td');
          const computerButton = document.createElement('button');
          computerButton.type = 'button';
          computerButton.className = 'link-button';
          computerButton.setAttribute('data-host-button', 'true');
          computerButton.setAttribute('data-host-id', host.id || '');
          computerButton.setAttribute('data-host-name', host.computer || '');
          computerButton.textContent = host.computer || 'Unnamed';
          computerCell.appendChild(computerButton);
          row.appendChild(computerCell);

          const groupCell = document.createElement('td');
          groupCell.textContent = host.group || '';
          row.appendChild(groupCell);

          const ipCell = document.createElement('td');
          ipCell.textContent = host.ip || '';
          row.appendChild(ipCell);

          const statusCell = document.createElement('td');
          statusCell.className = statusClass(host.status);
          statusCell.textContent = host.status || 'unknown';
          row.appendChild(statusCell);

          const updatedCell = document.createElement('td');
          updatedCell.textContent = host.last_update || '–';
          row.appendChild(updatedCell);

          tableBody.appendChild(row);
        });

        attachHostHandlers();
      };

      const fetchHosts = () => {
        const params = new URLSearchParams(window.location.search);
        const query = params.toString();
        const url = '/api/hosts' + (query ? `?${query}` : '');
        fetch(url, { headers: { 'Accept': 'application/json' } })
          .then((response) => {
            if (!response.ok) {
              throw new Error('Network response was not ok');
            }
            return response.json();
          })
          .then((data) => {
            if (data && Array.isArray(data.hosts)) {
              renderHosts(data.hosts);
            }
          })
          .catch(() => {
            // Ignore refresh errors; the worker will try again on the next interval.
          });
      };

      fetchHosts();
      setInterval(fetchHosts, 5000);
      attachHostHandlers();
    })();
    </script>
    """

    content = add_form + table_html + modal_html + auto_refresh_script
    return render_template("Dashboard", content)


def settings_page(message: str | None = None) -> bytes:
    alert = f"<p>{html_escape(message)}</p>" if message else ""
    content = f"""
    <h2>Settings</h2>
    {alert}
    <form method=\"post\" action=\"/settings\">
      <label>Current password <input type=\"password\" name=\"current_password\" required></label><br>
      <label>New password <input type=\"password\" name=\"new_password\" required></label><br>
      <label>Confirm password <input type=\"password\" name=\"confirm_password\" required></label><br>
      <button type=\"submit\">Update password</button>
    </form>
    """
    return render_template("Settings", content)


def login_page(error: str | None = None) -> bytes:
    alert = f"<p style='color:red;'>{html_escape(error)}</p>" if error else ""
    content = f"""
    <h2>Login</h2>
    {alert}
    <form method=\"post\" action=\"/login\">
      <label>Username <input type=\"text\" name=\"username\" required></label><br>
      <label>Password <input type=\"password\" name=\"password\" required></label><br>
      <button type=\"submit\">Login</button>
    </form>
    """
    return render_template("Login", content, user_authenticated=False)


def parse_cookies(environ: dict) -> cookies.SimpleCookie:
    jar = cookies.SimpleCookie()
    raw = environ.get("HTTP_COOKIE")
    if raw:
        jar.load(raw)
    return jar


def application_factory(store: DataStore, sessions: SessionStore):
    def application(environ, start_response):
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET").upper()
        query = {k: v[0] for k, v in urllib.parse.parse_qs(environ.get("QUERY_STRING", "")).items()}

        jar = parse_cookies(environ)
        sid = jar.get("session_id").value if jar.get("session_id") else None
        authenticated = sessions.validate(sid)

        if path == "/login":
            if method == "POST":
                data = parse_post(environ)
                username = data.get("username", "")
                password = data.get("password", "")
                if username == "admin" and store.verify_password(password):
                    sid_new = sessions.create()
                    headers = []
                    cookie = cookies.SimpleCookie()
                    cookie["session_id"] = sid_new
                    cookie["session_id"]["path"] = "/"
                    headers.extend(("Set-Cookie", morsel.OutputString()) for morsel in cookie.values())
                    status, extra_headers, body = redirect("/")
                    headers.extend(extra_headers)
                    start_response(status, headers)
                    return [body]
                return _respond(start_response, "200 OK", login_page("Invalid credentials."))
            return _respond(start_response, "200 OK", login_page())

        if path == "/logout":
            sessions.destroy(sid)
            status, headers, body = redirect("/login")
            cookie = cookies.SimpleCookie()
            cookie["session_id"] = ""
            cookie["session_id"]["path"] = "/"
            cookie["session_id"]["max-age"] = 0
            headers.extend(("Set-Cookie", morsel.OutputString()) for morsel in cookie.values())
            start_response(status, headers)
            return [body]

        if not authenticated:
            status, headers, body = redirect("/login")
            start_response(status, headers)
            return [body]

        if path == "/":
            content = dashboard_page(store, query)
            return _respond(start_response, "200 OK", content)

        if path == "/api/hosts":
            hosts, *_ = filter_and_sort_hosts(store, query)
            payload = {
                "hosts": [
                    {
                        "id": host.get("id"),
                        "computer": host.get("computer", ""),
                        "group": host.get("group", ""),
                        "ip": host.get("ip", ""),
                        "status": host.get("status", "unknown"),
                        "last_update": _format_ts(host.get("last_update")),
                    }
                    for host in hosts
                ]
            }
            return json_response(start_response, "200 OK", payload)

        if path == "/api/host_log":
            host_id = query.get("host_id", "").strip()
            if not host_id:
                return json_response(start_response, "400 Bad Request", {"error": "host_id is required"})
            host = store.get_host(host_id)
            if not host:
                return json_response(start_response, "404 Not Found", {"error": "Host not found"})
            entries = store.get_host_log(host_id)
            payload = {
                "host": {
                    "id": host.get("id"),
                    "computer": host.get("computer", ""),
                    "group": host.get("group", ""),
                    "ip": host.get("ip", ""),
                },
                "entries": [
                    {
                        "ts": float(entry.get("ts", 0.0)),
                        "timestamp": entry.get("timestamp", ""),
                        "status": entry.get("status", "unknown"),
                    }
                    for entry in entries
                ],
            }
            return json_response(start_response, "200 OK", payload)

        if path == "/add" and method == "POST":
            data = parse_post(environ)
            computer = data.get("computer", "").strip()
            group = data.get("group", "").strip()
            ip = data.get("ip", "").strip()
            if computer and ip:
                store.add_host(computer, group, ip)
            status, headers, body = redirect("/")
            start_response(status, headers)
            return [body]

        if path == "/settings":
            if method == "POST":
                data = parse_post(environ)
                current = data.get("current_password", "")
                new = data.get("new_password", "")
                confirm = data.get("confirm_password", "")
                if not store.verify_password(current):
                    return _respond(start_response, "200 OK", settings_page("Incorrect current password."))
                if not new:
                    return _respond(start_response, "200 OK", settings_page("New password cannot be empty."))
                if new != confirm:
                    return _respond(start_response, "200 OK", settings_page("Passwords do not match."))
                store.update_password(new)
                return _respond(start_response, "200 OK", settings_page("Password updated."))
            return _respond(start_response, "200 OK", settings_page())

        return _respond(start_response, "404 Not Found", render_template("Not Found", "<p>Page not found.</p>"))

    return application


def _respond(start_response, status: str, body: bytes):
    headers = [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))]
    start_response(status, headers)
    return [body]


def json_response(start_response, status: str, payload: dict):
    body = json.dumps(payload).encode("utf-8")
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    start_response(status, headers)
    return [body]


def main() -> None:
    store = DataStore(DATA_FILE)
    sessions = SessionStore()
    worker = PingWorker(store)
    worker.start()

    with make_server("0.0.0.0", 80, application_factory(store, sessions)) as httpd:
        print("Serving on http://localhost:80")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            worker.stop()


if __name__ == "__main__":
    main()
