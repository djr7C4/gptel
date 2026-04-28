;;; gptel-openai-codex-oauth.el --- Codex OAuth support for gptel  -*- lexical-binding: t; -*-

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;;

;;; Code:
(require 'cl-lib)
(require 'browse-url)
(require 'subr-x)
(require 'gptel-request)

(defvar url-http-end-of-headers)
(defvar url-http-response-status)
(declare-function secrets-create-item "secrets")
(declare-function secrets-delete-item "secrets")
(declare-function secrets-get-secret "secrets")
(declare-function secrets-search-items "secrets")

(defconst gptel--openai-chatgpt-client-id "app_EMoamEEZ73f0CkXaXp7hrann"
  "OAuth client id used by OpenAI Codex device login.")

(defcustom gptel-openai-chatgpt-auth-file nil
  "Obsolete file containing ChatGPT OAuth tokens from Codex.
ChatGPT OAuth tokens are now read from the OS keyring instead."
  :type '(choice (const :tag "Unused" nil) file)
  :group 'gptel)

(defcustom gptel-openai-chatgpt-auth-url "https://auth.openai.com"
  "OpenAI OAuth issuer URL used for ChatGPT OAuth."
  :type 'string
  :group 'gptel)

(defcustom gptel-openai-chatgpt-keyring-collection "default"
  "Secret Service collection used to store ChatGPT OAuth tokens."
  :type 'string
  :group 'gptel)

(defcustom gptel-openai-chatgpt-token-refresh-skew 300
  "Seconds before expiry when ChatGPT OAuth access tokens are refreshed."
  :type 'natnum
  :group 'gptel)

(defcustom gptel-openai-chatgpt-callback-port 1455
  "Localhost port used for ChatGPT OAuth browser login."
  :type 'natnum
  :group 'gptel)

(defconst gptel--openai-chatgpt-keyring-label "gptel ChatGPT OAuth")

(defun gptel--openai-chatgpt-base-url ()
  "Return `gptel-openai-chatgpt-auth-url' without trailing slashes."
  (string-remove-suffix "/" gptel-openai-chatgpt-auth-url))

(defun gptel--openai-chatgpt-keyword (key)
  "Return plist keyword for JSON KEY."
  (intern (concat ":" key)))

(defun gptel--openai-chatgpt-post (url data content-type)
  "POST DATA to URL with CONTENT-TYPE and return (STATUS . JSON)."
  (let ((url-request-method "POST")
        (url-request-data (encode-coding-string data 'utf-8))
        (url-mime-accept-string "application/json")
        (url-request-extra-headers `(("content-type" . ,content-type))))
    (with-current-buffer (or (url-retrieve-synchronously url 'silent)
                             (user-error "No response from %s" url))
      (unwind-protect
          (progn
            (goto-char url-http-end-of-headers)
            (cons url-http-response-status
                  (unless (eobp)
                    (condition-case nil (gptel--json-read)
                      (error nil)))))
        (kill-buffer)))))

(defun gptel--openai-chatgpt-post-json (url data)
  "POST DATA as JSON to URL and return (STATUS . JSON)."
  (gptel--openai-chatgpt-post
   url (gptel--json-encode data) "application/json"))

(defun gptel--openai-chatgpt-post-form (url data)
  "POST DATA as form-urlencoded to URL and return (STATUS . JSON)."
  (gptel--openai-chatgpt-post
   url
   (mapconcat (pcase-lambda (`(,key . ,value))
                (concat (url-hexify-string key)
                        "="
                        (url-hexify-string value)))
              data "&")
   "application/x-www-form-urlencoded"))

(defun gptel--openai-chatgpt-decode-jwt (jwt)
  "Decode JWT payload into a plist."
  (when (and (stringp jwt)
             (string-match-p "\\`[^.]+\\.[^.]+\\.[^.]+\\'" jwt))
    (let* ((payload (cadr (split-string jwt "\\.")))
           (payload (replace-regexp-in-string "-" "+" payload nil t))
           (payload (replace-regexp-in-string "_" "/" payload nil t))
           (padding (make-string (mod (- 4 (mod (length payload) 4)) 4) ?=)))
      (gptel--json-read-string
       (decode-coding-string
        (base64-decode-string (concat payload padding))
        'utf-8)))))

(defun gptel--openai-chatgpt-jwt-claim (jwt key)
  "Return top-level claim KEY from JWT."
  (plist-get (gptel--openai-chatgpt-decode-jwt jwt)
             (gptel--openai-chatgpt-keyword key)))

(defun gptel--openai-chatgpt-auth-claim (jwt key)
  "Return ChatGPT auth claim KEY from JWT."
  (plist-get
   (plist-get (gptel--openai-chatgpt-decode-jwt jwt)
              (gptel--openai-chatgpt-keyword
               "https://api.openai.com/auth"))
   (gptel--openai-chatgpt-keyword key)))

(defun gptel--openai-chatgpt-token-expired-p (token)
  "Return non-nil if TOKEN is missing or near expiry."
  (let ((exp (gptel--openai-chatgpt-jwt-claim token "exp")))
    (and (numberp exp)
         (<= exp (+ (float-time)
                    gptel-openai-chatgpt-token-refresh-skew)))))

(defun gptel--openai-chatgpt-token-plist (tokens)
  "Normalize TOKENS for keyring storage."
  (let* ((id-token (plist-get tokens :id_token))
         (access-token (plist-get tokens :access_token))
         (refresh-token (plist-get tokens :refresh_token))
         (account-id (or (plist-get tokens :account_id)
                         (gptel--openai-chatgpt-auth-claim
                          id-token "chatgpt_account_id"))))
    (unless (and id-token access-token refresh-token)
      (user-error "OpenAI OAuth response did not include all tokens"))
    (list :tokens
          (list :id_token id-token
                :access_token access-token
                :refresh_token refresh-token
                :account_id account-id))))

(defun gptel--openai-chatgpt-base64url (string &optional no-pad)
  "Return base64url-encoded STRING.
When NO-PAD is non-nil, strip trailing padding."
  (if (fboundp 'base64url-encode-string)
      (base64url-encode-string string no-pad)
    (let ((encoded (base64-encode-string string t)))
      (setq encoded (replace-regexp-in-string "+" "-" encoded nil t))
      (setq encoded (replace-regexp-in-string "/" "_" encoded nil t))
      (if no-pad
          (replace-regexp-in-string "=+\\'" "" encoded)
        encoded))))

(defun gptel--openai-chatgpt-random-string (&optional bytes)
  "Return a random base64url string using BYTES random bytes."
  (gptel--openai-chatgpt-base64url
   (apply #'unibyte-string
          (cl-loop repeat (or bytes 32) collect (random 256)))
   t))

(defun gptel--openai-chatgpt-pkce ()
  "Return a plist containing PKCE code verifier and challenge."
  (let* ((verifier (gptel--openai-chatgpt-random-string 32))
         (challenge
          (gptel--openai-chatgpt-base64url
           (secure-hash 'sha256 verifier nil nil t)
           t)))
    (list :verifier verifier :challenge challenge)))

(defun gptel--openai-chatgpt-query-value (query key)
  "Return KEY from URL QUERY."
  (cdr (assoc key
              (mapcar
               (lambda (part)
                 (let* ((kv (split-string part "="))
                        (name (car kv))
                        (value (mapconcat #'identity (cdr kv) "=")))
                   (cons (url-unhex-string name)
                         (url-unhex-string value))))
               (split-string (or query "") "[&;]" t)))))

(defun gptel--openai-chatgpt-auth-url (redirect-uri pkce state)
  "Return browser authorization URL for REDIRECT-URI, PKCE and STATE."
  (concat
   (gptel--openai-chatgpt-base-url)
   "/oauth/authorize?"
   (mapconcat
    (pcase-lambda (`(,key . ,value))
      (concat (url-hexify-string key)
              "="
              (url-hexify-string value)))
    `(("response_type" . "code")
      ("client_id" . ,gptel--openai-chatgpt-client-id)
      ("redirect_uri" . ,redirect-uri)
      ("scope" . "openid profile email offline_access api.connectors.read api.connectors.invoke")
      ("code_challenge" . ,(plist-get pkce :challenge))
      ("code_challenge_method" . "S256")
      ("id_token_add_organizations" . "true")
      ("codex_cli_simplified_flow" . "true")
      ("state" . ,state)
      ("originator" . "codex_cli_rs"))
    "&")))

(defun gptel--openai-chatgpt-keyring-ensure ()
  "Ensure Secret Service support is available."
  (unless (and (require 'secrets nil t)
               (fboundp 'secrets-create-item))
    (user-error "Emacs Secret Service support is unavailable"))
  (condition-case err
      (secrets-search-items gptel-openai-chatgpt-keyring-collection
                            :application "gptel"
                            :service gptel--openai-chatgpt-keyring-label)
    (error (user-error "OS keyring is unavailable: %s"
                       (error-message-string err)))))

(defun gptel--openai-chatgpt-keyring-load ()
  "Load ChatGPT OAuth tokens from the OS keyring."
  (gptel--openai-chatgpt-keyring-ensure)
  (when-let* ((secret
               (secrets-get-secret gptel-openai-chatgpt-keyring-collection
                                   gptel--openai-chatgpt-keyring-label)))
    (gptel--json-read-string secret)))

(defun gptel--openai-chatgpt-keyring-save (auth)
  "Save AUTH to the OS keyring."
  (gptel--openai-chatgpt-keyring-ensure)
  (dolist (item (secrets-search-items
                 gptel-openai-chatgpt-keyring-collection
                 :application "gptel"
                 :service gptel--openai-chatgpt-keyring-label))
    (ignore-errors
      (secrets-delete-item gptel-openai-chatgpt-keyring-collection item)))
  (secrets-create-item
   gptel-openai-chatgpt-keyring-collection
   gptel--openai-chatgpt-keyring-label
   (gptel--json-encode auth)
   :application "gptel"
   :service gptel--openai-chatgpt-keyring-label
   :host "auth.openai.com"
   :user "chatgpt-oauth")
  auth)

(defun gptel--openai-chatgpt-refresh-token (auth)
  "Refresh ChatGPT OAuth AUTH and store the new tokens."
  (let* ((tokens (plist-get auth :tokens))
         (refresh-token (plist-get tokens :refresh_token))
         (base-url (gptel--openai-chatgpt-base-url))
         (response
          (gptel--openai-chatgpt-post-json
           (concat base-url "/oauth/token")
           `(:client_id ,gptel--openai-chatgpt-client-id
             :grant_type "refresh_token"
             :refresh_token ,refresh-token)))
         (status (car response))
         (body (cdr response)))
    (unless (and (>= status 200) (< status 300) body)
      (user-error "OpenAI OAuth token refresh failed with status %s" status))
    (gptel--openai-chatgpt-keyring-save
     (gptel--openai-chatgpt-token-plist
      (list :id_token (or (plist-get body :id_token)
                          (plist-get tokens :id_token))
            :access_token (or (plist-get body :access_token)
                              (plist-get tokens :access_token))
            :refresh_token (or (plist-get body :refresh_token)
                               refresh-token)
            :account_id (plist-get tokens :account_id))))))

(defun gptel--openai-chatgpt-exchange-code (code redirect-uri pkce)
  "Exchange OAuth CODE for ChatGPT tokens.
REDIRECT-URI and PKCE must match the authorization request."
  (let* ((base-url (gptel--openai-chatgpt-base-url))
         (response
          (gptel--openai-chatgpt-post-form
           (concat base-url "/oauth/token")
           `(("grant_type" . "authorization_code")
             ("code" . ,code)
             ("redirect_uri" . ,redirect-uri)
             ("client_id" . ,gptel--openai-chatgpt-client-id)
             ("code_verifier" . ,(plist-get pkce :verifier)))))
         (status (car response))
         (body (cdr response)))
    (unless (and (>= status 200) (< status 300) body)
      (user-error "OpenAI OAuth token exchange failed with status %s" status))
    (gptel--openai-chatgpt-keyring-save
     (gptel--openai-chatgpt-token-plist body))))

(defun gptel--openai-chatgpt-callback-response (message)
  "Return a minimal HTTP response containing MESSAGE."
  (concat "HTTP/1.1 200 OK\r\n"
          "Content-Type: text/plain; charset=utf-8\r\n"
          "Connection: close\r\n"
          "Content-Length: " (number-to-string (string-bytes message)) "\r\n"
          "\r\n"
          message))

(defun gptel--openai-chatgpt-read-callback (server state)
  "Wait for OAuth callback on SERVER and return the authorization code.
STATE is the OAuth state value that must be returned by OpenAI."
  (let ((result nil)
        (deadline (+ (float-time) (* 5 60))))
    (cl-labels
        ((handler
          (proc string)
          (let ((request (concat (or (process-get proc :request) "") string)))
            (process-put proc :request request)
            (when (string-match-p "\r?\n\r?\n" request)
              (let* ((path (and (string-match "\\`GET \\([^ ]+\\) " request)
                                (match-string 1 request)))
                     (query (and path
                                 (string-match "\\?\\(.*\\)\\'" path)
                                 (match-string 1 path)))
                     (code (gptel--openai-chatgpt-query-value query "code"))
                     (returned-state
                      (gptel--openai-chatgpt-query-value query "state"))
                     (error (gptel--openai-chatgpt-query-value query "error"))
                     (description
                      (gptel--openai-chatgpt-query-value
                       query "error_description")))
                (cond
                 ((and code (equal returned-state state))
                  (setq result (list :code code))
                  (process-send-string
                   proc
                   (gptel--openai-chatgpt-callback-response
                    "ChatGPT authorization complete.  You can close this tab.")))
                 (error
                  (setq result
                        (list :error
                              (if description
                                  (format "%s: %s" error description)
                                error)))
                  (process-send-string
                   proc
                   (gptel--openai-chatgpt-callback-response
                    "ChatGPT authorization failed.  Return to Emacs.")))
                 (t
                  (process-send-string
                   proc
                   (gptel--openai-chatgpt-callback-response
                    "Invalid ChatGPT authorization callback."))))
                (delete-process proc))))))
      (set-process-filter server #'handler)
      (while (and (not result)
                  (process-live-p server)
                  (< (float-time) deadline))
        (accept-process-output nil 1))
      (unless result
        (user-error "Timed out waiting for ChatGPT OAuth callback"))
      (when-let* ((error (plist-get result :error)))
        (user-error "ChatGPT authorization failed: %s" error))
      (plist-get result :code))))

(defun gptel--openai-chatgpt-login-browser ()
  "Request ChatGPT OAuth tokens using browser authorization."
  (let* ((pkce (gptel--openai-chatgpt-pkce))
         (state (gptel--openai-chatgpt-random-string 32))
         (server
          (make-network-process
           :name "gptel-chatgpt-oauth"
           :server t
           :host 'local
           :service gptel-openai-chatgpt-callback-port
           :noquery t))
         (port (process-contact server :service))
         (redirect-uri (format "http://localhost:%d/auth/callback" port))
         (auth-url (gptel--openai-chatgpt-auth-url redirect-uri pkce state)))
    (unwind-protect
        (progn
          (browse-url auth-url)
          (message "Opened ChatGPT authorization in your browser.")
          (gptel--openai-chatgpt-exchange-code
           (gptel--openai-chatgpt-read-callback server state)
           redirect-uri pkce))
      (when (process-live-p server)
        (delete-process server)))))

;;;###autoload
(defun gptel-openai-chatgpt-login ()
  "Request ChatGPT OAuth tokens from OpenAI and store them in the OS keyring."
  (interactive)
  (prog1 (gptel--openai-chatgpt-login-browser)
    (message "Stored ChatGPT OAuth tokens in the OS keyring.")))

(defun gptel--openai-chatgpt-auth ()
  "Read, request or refresh ChatGPT OAuth tokens from the OS keyring."
  (let* ((auth (gptel--openai-chatgpt-keyring-load))
         (tokens (plist-get auth :tokens))
         (access-token (plist-get tokens :access_token)))
    (cond
     ((not auth)
      (gptel-openai-chatgpt-login))
     ((and (plist-get tokens :refresh_token)
           (gptel--openai-chatgpt-token-expired-p access-token))
      (gptel--openai-chatgpt-refresh-token auth))
     (t auth))))

(defun gptel--openai-chatgpt-header (_info)
  "Return ChatGPT OAuth headers for the OpenAI Responses API."
  (let* ((auth (gptel--openai-chatgpt-auth))
         (tokens (plist-get auth :tokens))
         (access-token (plist-get tokens :access_token))
         (account-id (plist-get tokens :account_id)))
    (unless (and access-token account-id)
      (user-error "ChatGPT OAuth tokens are missing access token or account id"))
    `(("Authorization" . ,(concat "Bearer " access-token))
      ("ChatGPT-Account-ID" . ,account-id))))

(provide 'gptel-openai-codex-oauth)
;;; gptel-openai-codex-oauth.el ends here
