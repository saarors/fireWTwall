# Server-Side Template Injection (SSTI) Rules

The WAF applies 18 SSTI rules. All rules are `critical` severity.

**Scanned sources:** query params, request body, URL path, cookies.

SSTI occurs when user input is embedded directly into a server-side template and evaluated by the template engine. In the worst case it leads to Remote Code Execution (RCE) because template engines can access the host language's standard library.

---

## Python / Jinja2 / Mako

Jinja2 and Mako (used in Flask, FastAPI, and Pyramid) expose the Python object model through template expressions wrapped in `{{ }}`.

| Rule ID | Pattern | Example payload | CVE / Tool |
|---------|---------|-----------------|------------|
| `ssti-python-class` | `{{.*__class__.*}}` | `{{''.__class__}}` | tplmap, various PoCs |
| `ssti-python-mro` | `{{.*__mro__.*}}` | `{{''.__class__.__mro__}}` | Traverses class hierarchy to reach `object` |
| `ssti-python-subclasses` | `{{.*__subclasses__()` | `{{''.__class__.__mro__[1].__subclasses__()}}` | Lists all loaded classes to find `subprocess.Popen` |
| `ssti-python-popen` | `{{.*popen(` / `subprocess.` | `{{request.application.__globals__['__builtins__']['__import__']('os').popen('id').read()}}` | OS command execution |
| `ssti-python-globals` | `{{.*__globals__.*}}` | `{{lipsum.__globals__['os'].popen('id').read()}}` | Access globals dict to reach `os` module |
| `ssti-python-builtins` | `{{.*__builtins__.*}}` | `{{''.__class__.__mro__[1].__subclasses__()[91].__init__.__globals__['__builtins__']['exec']('...')}}` | Access built-in functions including `exec` and `eval` |

```bash
curl "http://localhost:3000/?name={{__class__.__mro__}}"
curl "http://localhost:3000/?name={{request.application.__globals__['os'].popen('id').read()}}"
```

---

## Twig (PHP)

Twig is used by Symfony, Drupal, and many PHP frameworks. `_self` in Twig gives access to the Twig environment.

| Rule ID | Pattern | Example payload |
|---------|---------|-----------------|
| `ssti-twig-self` | `{{_self.env.` | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| `ssti-twig-filter` | `registerUndefinedFilterCallback` | `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}` |

```bash
curl "http://localhost:3000/?tpl={{_self.env.registerUndefinedFilterCallback('exec')}}"
```

---

## FreeMarker (Java)

FreeMarker is used by Apache Struts, Spring MVC, and JBoss Seam.

| Rule ID | Pattern | Example payload | CVE |
|---------|---------|-----------------|-----|
| `ssti-freemarker` | `<#assign.*Execute` / `freemarker.template.utility.Execute` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | CVE-2015-5211, Metasploit module |

```bash
curl 'http://localhost:3000/?template=<#assign+ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
```

---

## Apache Velocity (Java)

Velocity is used by Apache Struts and other Java frameworks.

| Rule ID | Pattern | Example payload |
|---------|---------|-----------------|
| `ssti-velocity` | `#set.*$class` / `#set.*Runtime` | `#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))` |

---

## Smarty (PHP)

Smarty is a PHP template engine with built-in PHP execution tags.

| Rule ID | Pattern | Example payload |
|---------|---------|-----------------|
| `ssti-smarty-php` | `{php}` / `{/php}` | `{php}echo shell_exec('id');{/php}` |
| `ssti-smarty-system` | `{system(` / `{passthru(` | `{system('id')}` |

```bash
curl "http://localhost:3000/?tpl={php}echo+shell_exec('id');{/php}"
```

---

## Ruby ERB

ERB is built into Ruby and used by Rails.

| Rule ID | Pattern | Example payload |
|---------|---------|-----------------|
| `ssti-erb` | `<%= system/exec/%x/IO.popen` | `<%= system('id') %>` |

```bash
curl "http://localhost:3000/?template=<%=+system('id')+%>"
```

---

## Java EL / Spring

Java Expression Language is used in JSP, JSF, and Spring.

| Rule ID | Pattern | Example payload | CVE |
|---------|---------|-----------------|-----|
| `ssti-java-runtime` | `${.*Runtime.*exec` / `${.*ProcessBuilder` | `${T(java.lang.Runtime).getRuntime().exec('id')}` | Spring EL injection |

---

## Struts2 / OGNL

OGNL (Object Graph Navigation Language) is the expression language used by Apache Struts2.

| Rule ID | Pattern | Example payload | CVE |
|---------|---------|-----------------|-----|
| `ssti-ognl-expression` | `%{#[a-zA-Z_]` / `%25{#` / `${#context[` | `%{#a=new java.lang.ProcessBuilder({'id'}).start()}` | CVE-2017-5638, CVE-2018-11776, many Metasploit modules |
| `ssti-ognl-member` | `#_memberAccess` / `@java.lang.Runtime` / `new java.lang.ProcessBuilder` | `%{#_memberAccess["allowPrivateAccess"]=true,@java.lang.Runtime@getRuntime().exec('id')}` | CVE-2013-2251 |

```bash
curl "http://localhost:3000/?redirect:%25{#a=new+java.lang.ProcessBuilder({'id'}).start()}"
```

---

## Spring4Shell

Spring4Shell (CVE-2022-22965) abuses the Spring Framework's data binding to write a JSP web shell by accessing the class loader through a bean property path.

| Rule ID | Pattern | Example payload | CVE |
|---------|---------|-----------------|-----|
| `ssti-spring-classloader` | `class.module.classLoader` / `class.classLoader.urls` | `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25{prefix}i` | CVE-2022-22965 |

```bash
curl "http://localhost:3000/?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
```

---

## Tornado (Python)

Tornado is a Python web framework with its own template engine. `{% import %}` in a Tornado template gives access to Python modules.

| Rule ID | Pattern | Example payload |
|---------|---------|-----------------|
| `ssti-tornado-import` | `{% import os %}` | `{% import os %}{{ os.popen('id').read() }}` |

```bash
curl "http://localhost:3000/?name={%+import+os+%}{{+os.popen('id').read()+}}"
```
