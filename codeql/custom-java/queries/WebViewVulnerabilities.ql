/**
 * @name Insecure WebView usage
 * @description Detects potentially insecure use of WebView in Android apps
 * @kind path-problem
 * @problem.severity warning
 * @id android/insecure-webview
 * @tags security
 *       android
 *       webview
 */

import java
import semmle.code.java.security.AndroidWebView
import semmle.code.java.controlflow.DataFlow
import DataFlow::PathGraph

class InsecureJavaScriptInterfaceCall extends Expr {
  InsecureJavaScriptInterfaceCall() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("addJavascriptInterface") and
      ma.getQualifier().getType().hasQualifiedName("android.webkit", "WebView") and
      this = ma
    )
  }
}

class JavaScriptEnabledCall extends Expr {
  JavaScriptEnabledCall() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("setJavaScriptEnabled") and
      ma.getQualifier().getType().getName() = "WebSettings" and
      this = ma
    )
  }
}

from Expr call
where call instanceof InsecureJavaScriptInterfaceCall or call instanceof JavaScriptEnabledCall
select call,
  "This WebView call may introduce security issues like RCE or XSS. Ensure this is absolutely needed."
