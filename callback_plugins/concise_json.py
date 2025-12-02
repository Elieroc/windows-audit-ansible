# callback_plugins/concise_json.py
from ansible.plugins.callback import CallbackBase
import json

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'concise_json'

    def __init__(self):
        super().__init__()
        self.results_by_host = {}

    def _store_result(self, host, task_name, msg):
        if host not in self.results_by_host:
            self.results_by_host[host] = []
        self.results_by_host[host].append(msg)

    def v2_runner_on_ok(self, result):
        host = result._host.get_name()
        msg = result._result.get('msg')
        if msg:
            # si msg est un dict (audit_status), stocke directement
            if isinstance(msg, dict):
                self._store_result(host, result.task_name, msg)
            else:
                self._store_result(host, result.task_name, {'task': result.task_name, 'msg': str(msg), 'audit_status': 'INFO'})

    def v2_runner_on_failed(self, result, ignore_errors=False):
        host = result._host.get_name()
        msg = result._result.get('msg') or result._result.get('stderr') or 'Task failed'
        self._store_result(host, result.task_name, {'task': result.task_name, 'msg': str(msg), 'audit_status': 'FAIL'})

    def v2_playbook_on_stats(self, stats):
        from datetime import datetime
        output = []
        for host, tasks in self.results_by_host.items():
            output.append({
                'host': host,
                'tasks': tasks
            })
        filename = f"exports/audit-{datetime.now().strftime('%F_%H-%M-%S')}.json"
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nJSON exporté : {filename}")
