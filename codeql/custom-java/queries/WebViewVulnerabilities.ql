/**
 * @name WebView Security Vulnerabilities
 * @description Detects insecure WebView configurations and unsafe URL loading
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id java/webview-security-issues
 * @tags security
 *       external/cwe/cwe-79
 *       external/cwe/cwe-200
 */

import java

// Detect WebView.loadUrl() calls with untrusted input
class UnsafeWebViewLoadUrl extends MethodAccess {
  UnsafeWebViewLoadUrl() {
    this.getMethod().hasName("loadUrl") and
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebView") and
    (
      // Direct Intent data usage
      this.getArgument(0).(MethodAccess).getMethod().hasName("getStringExtra") or
      this.getArgument(0).(MethodAccess).getMethod().hasName("getDataString") or
      this.getArgument(0).(MethodAccess).getMethod().hasName("getData") or
      // Any external input without validation
      exists(Parameter p | 
        this.getArgument(0) = p.getAnAccess() and
        not exists(IfStmt validation |
          validation.getCondition().getAChildExpr*() = p.getAnAccess()
        )
      )
    )
  }
}

// Detect dangerous WebView settings
class DangerousWebViewSetting extends MethodAccess {
  DangerousWebViewSetting() {
    this.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebSettings") and
    (
      (this.getMethod().hasName("setAllowFileAccessFromFileURLs") and
       this.getArgument(0).(BooleanLiteral).getBooleanValue() = true) or
      (this.getMethod().hasName("setAllowUniversalAccessFromFileURLs") and
       this.getArgument(0).(BooleanLiteral).getBooleanValue() = true) or
      (this.getMethod().hasName("setAllowFileAccess") and
       this.getArgument(0).(BooleanLiteral).getBooleanValue() = true) or
      (this.getMethod().hasName("setJavaScriptEnabled") and
       this.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
       // Flag if combined with file access
       exists(DangerousWebViewSetting other |
         other != this and
         other.getEnclosingCallable() = this.getEnclosingCallable() and
         other.getMethod().hasName("setAllowFileAccessFromFileURLs")
       ))
    )
  }
}

// Detect WebViewClient without proper URL validation
class InsecureWebViewClient extends ClassInstanceExpr {
  InsecureWebViewClient() {
    this.getType().(RefType).hasQualifiedName("android.webkit", "WebViewClient") and
    not exists(Method m |
      m.getDeclaringType() = this.getType() and
      m.hasName("shouldOverrideUrlLoading")
    ) and
    // Check if this is used with setWebViewClient
    exists(MethodAccess setClient |
      setClient.getMethod().hasName("setWebViewClient") and
      setClient.getArgument(0) = this
    )
  }
}

// Main query
from Expr issue, string message, string category
where
  (
    issue instanceof UnsafeWebViewLoadUrl and
    message = "WebView loads URL from untrusted source without validation. This could allow malicious apps to load arbitrary content including file:// URLs or execute JavaScript attacks." and
    category = "Unsafe URL Loading"
  ) or
  (
    issue instanceof DangerousWebViewSetting and
    message = "Dangerous WebView setting detected. " + 
      (if issue.(MethodAccess).getMethod().hasName("setAllowFileAccessFromFileURLs") 
       then "setAllowFileAccessFromFileURLs(true) allows JavaScript to access local files."
       else if issue.(MethodAccess).getMethod().hasName("setAllowUniversalAccessFromFileURLs")
       then "setAllowUniversalAccessFromFileURLs(true) allows cross-origin requests from file URLs."
       else if issue.(MethodAccess).getMethod().hasName("setAllowFileAccess")
       then "setAllowFileAccess(true) allows access to file system."
       else "JavaScript enabled with dangerous file access settings.") and
    category = "Dangerous WebView Configuration"
  ) or
  (
    issue instanceof InsecureWebViewClient and
    message = "WebViewClient used without overriding shouldOverrideUrlLoading() method. This allows unrestricted navigation to any URL." and
    category = "Missing URL Validation"
  )
select issue, "[" + category + "] " + message
