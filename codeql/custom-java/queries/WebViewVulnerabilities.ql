/**
 * @name WebView Security Check
 * @description Simple pattern matching for WebView security issues
 * @kind problem
 * @problem.severity warning
 * @id custom/webview-simple
 * @tags security
 */

import java

from Method m, string message
where
  // Check method names that are potentially unsafe
  (m.getName() = "setJavaScriptEnabled" and
   message = "JavaScript may be enabled in WebView") or
  
  (m.getName() = "setAllowFileAccessFromFileURLs" and
   message = "File access from file URLs may be enabled") or
   
  (m.getName() = "setAllowUniversalAccessFromFileURLs" and
   message = "Universal access from file URLs may be enabled") or
   
  (m.getName() = "addJavascriptInterface" and
   message = "JavaScript interface may be added to WebView") or
   
  (m.getName() = "loadUrl" and 
   m.getDeclaringType().getName() = "WebView" and
   message = "WebView loads URL - verify safety")
   
select m, message
