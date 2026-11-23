```python
import os as o
import subprocess as sp
from os import environ as env, getenv
from subprocess import run as launch
o.environ["SUBSCRIPT"]
env.get("GET")
getenv("GETENV")
"MEMBER" in env
"ABSENT" not in o.environ
env["STORE"] = "value"
del o.environ["DELETE"]
env.pop("POP")
env.setdefault("DEFAULT", "value")
env.update({"UPDATE": "value"}, KEYWORD="value")
o.putenv("PUT", "value")
o.unsetenv("UNSET")
sp.run([], env={"CHILD": "value"})
launch([], env={**env, "EXTRA": "value"})
sp.Popen([], env=env)
sp.run([], env=o.environ.copy())
sp.run([], env=dynamic)
o.execve("program", [], {"EXEC": "value"})
o.spawnvpe(0, "program", [], env={"SPAWN": "value"})
o.execlpe("program", "arg0", "arg1", {"EXEC_LIST": "value"})
for key in env:
    pass
[key for key in o.environ]
env[dynamic]
env[dynamic] = "value"
env.update(dynamic)
launch([], env={**dynamic})
env.update([("PAIR", "value"), dynamic_pair])
o.getenv(key="KEYWORD_GET")
env.get(*args)
```
