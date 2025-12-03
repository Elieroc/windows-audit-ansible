from ansible.plugins.callback import CallbackBase
import json

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'concise_json'

    def __init__(self):
        super().__init__()
        self.results_by_host = {}

    def _store_result(self, host, payload):
        if host not in self.results_by_host:
            self.results_by_host[host] = []
        self.results_by_host[host].append(payload)

    def v2_runner_on_ok(self, result):
        host = result._host.get_name()
        msg = result._result.get('msg')
        if not msg:
            return
        if isinstance(msg, dict):
            payload = msg
            if 'task' not in payload:
                payload['task'] = result.task_name
        else:
            payload = {
                'task': result.task_name,
                'msg': str(msg)
            }
        self._store_result(host, payload)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        host = result._host.get_name()
        msg = result._result.get('msg') or result._result.get('stderr') or 'Task failed'
        payload = msg if isinstance(msg, dict) else {'task': result.task_name, 'msg': str(msg)}
        if isinstance(payload, dict) and 'audit_status' not in payload:
            payload['audit_status'] = 'FAIL'
        self._store_result(host, payload)

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
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"\nConcise JSON exported: {filename}")
