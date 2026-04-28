;;; gptel-openai-responses.el --- Responses API support for gptel  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Karthik Chikmagalur

;; Author: Karthik Chikmagalur <karthikchikmagalur@gmail.com>
;; Keywords: comm

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
(require 'cl-generic)
(require 'cl-lib)
(require 'map)
(require 'gptel-request)
(require 'gptel-openai)
(require 'browse-url)

(defvar gptel-mode)
(defvar url-http-end-of-headers)
(defvar url-http-response-status)
(declare-function gptel-context--collect-media "gptel-context")
(declare-function secrets-create-item "secrets")
(declare-function secrets-delete-item "secrets")
(declare-function secrets-get-secret "secrets")
(declare-function secrets-search-items "secrets")

;;; OpenAI Responses
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

(defun gptel--openai-chatgpt-request-device-code ()
  "Request a ChatGPT OAuth device code from OpenAI."
  (let* ((base-url (gptel--openai-chatgpt-base-url))
         (response
          (gptel--openai-chatgpt-post-json
           (concat base-url "/api/accounts/deviceauth/usercode")
           `(:client_id ,gptel--openai-chatgpt-client-id)))
         (status (car response))
         (body (cdr response)))
    (unless (and (>= status 200) (< status 300) body)
      (user-error "OpenAI device code request failed with status %s" status))
    (let ((user-code (or (plist-get body :user_code)
                         (plist-get body :usercode)))
          (device-auth-id (plist-get body :device_auth_id)))
      (unless (and user-code device-auth-id)
        (user-error "OpenAI device code response was missing required data"))
      (list :verification_url (concat base-url "/codex/device")
            :user_code user-code
            :device_auth_id device-auth-id
            :interval (gptel--to-number (or (plist-get body :interval) 5))))))

(defun gptel--openai-chatgpt-poll-device-code (device-code)
  "Poll OpenAI until DEVICE-CODE is authorized."
  (let* ((base-url (gptel--openai-chatgpt-base-url))
         (url (concat base-url "/api/accounts/deviceauth/token"))
         (start (float-time))
         (max-wait (* 15 60))
         response status body)
    (while (progn
             (setq response
                   (gptel--openai-chatgpt-post-json
                    url
                    `(:device_auth_id
                      ,(plist-get device-code :device_auth_id)
                      :user_code ,(plist-get device-code :user_code)))
                   status (car response)
                   body (cdr response))
             (cond
              ((and (>= status 200) (< status 300)) nil)
              ((and (memq status '(403 404))
                    (< (- (float-time) start) max-wait))
               (sleep-for (plist-get device-code :interval))
               t)
              (t
               (user-error "OpenAI device authorization failed with status %s"
                           status)))))
    body))

(defun gptel--openai-chatgpt-exchange-device-code (code-response)
  "Exchange CODE-RESPONSE for ChatGPT OAuth tokens."
  (let* ((base-url (gptel--openai-chatgpt-base-url))
         (response
          (gptel--openai-chatgpt-post-form
           (concat base-url "/oauth/token")
           `(("grant_type" . "authorization_code")
             ("code" . ,(plist-get code-response :authorization_code))
             ("redirect_uri" . ,(concat base-url "/deviceauth/callback"))
             ("client_id" . ,gptel--openai-chatgpt-client-id)
             ("code_verifier" . ,(plist-get code-response :code_verifier)))))
         (status (car response))
         (body (cdr response)))
    (unless (and (>= status 200) (< status 300) body)
      (user-error "OpenAI OAuth token exchange failed with status %s" status))
    (gptel--openai-chatgpt-keyring-save
     (gptel--openai-chatgpt-token-plist body))))

;;;###autoload
(defun gptel-openai-chatgpt-login-device ()
  "Request ChatGPT OAuth tokens using device authorization.
This requires device code authorization to be enabled for Codex in
ChatGPT Security Settings."
  (interactive)
  (let* ((device-code (gptel--openai-chatgpt-request-device-code))
         (verification-url (plist-get device-code :verification_url))
         (user-code (plist-get device-code :user_code)))
    (when (fboundp 'gui-set-selection)
      (gui-set-selection 'CLIPBOARD user-code))
    (read-from-minibuffer
     (format "Code %s is copied.  Press RET to open %s. "
             user-code verification-url))
    (browse-url verification-url)
    (read-from-minibuffer "Press RET after authorizing ChatGPT. ")
    (prog1 (gptel--openai-chatgpt-exchange-device-code
            (gptel--openai-chatgpt-poll-device-code device-code))
      (message "Stored ChatGPT OAuth tokens in the OS keyring."))))

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

(defun gptel--openai-responses-update-tokens (usage info)
  "Update token usage information from USAGE.
USAGE is part of the response, INFO is the request plist."
  (when usage
    (let ((input (or (plist-get usage :input_tokens) 0))
          (output (or (plist-get usage :output_tokens) 0))
          (cached (or (map-nested-elt
                       usage '(:input_tokens_details :cached_tokens))
                      0)))
      ;; prompt_tokens includes the cached tokens, but we capture and display
      ;; the two exclusively in the UI.
      (let ((tokens (list :input (- input cached) :output output :cached cached)))
        (plist-put info :tokens tokens) ;Tokens for this turn
        (plist-put info :tokens-full    ;Tokens for full request
                   (gptel--sum-plists (plist-get info :tokens-full)
                                      tokens))))))

(cl-defmethod gptel-curl--parse-stream ((_backend gptel-openai-responses) info)
  "Parse an OpenAI Responses API data stream.

Return the text response accumulated since the last call to this
function.  Additionally, mutate state INFO to add tool-use
information if the stream contains it."
  (let ((content-strs) wait)
    (condition-case nil
        (while (and (not wait) (re-search-forward "^event: *\\(.+\\)" nil t))
          (let ((event-type (match-string 1)) data)
            (forward-line 1)
            (if (not (looking-at "data:" t))
                (progn (goto-char (match-beginning 0)) ;not enough data, reset
                       (setq wait t))
              (forward-char 5)
              (setq data (gptel--json-read))
              (pcase event-type
                ;; Text content delta
                ("response.output_text.delta"
                 (when-let* ((delta (plist-get data :delta))
                             ((not (string-empty-p delta))))
                   (push delta content-strs)))
                ;; Function call arguments delta
                ("response.function_call_arguments.delta"
                 (when-let* ((delta (plist-get data :delta)))
                   (plist-put info :partial_json
                              (cons delta (plist-get info :partial_json)))))
                ;; Function call completed (user-defined tools)
                ("response.output_item.done"
                 (when-let* ((item (plist-get data :item))
                             ((equal (plist-get item :type) "function_call"))
                             (tool-call
                              (list :id (plist-get item :call_id)
                                    :name (plist-get item :name)
                                    :args (ignore-errors
                                            (gptel--json-read-string
                                             (plist-get item :arguments))))))
                   (plist-put info :tool-use
                              (cons tool-call (plist-get info :tool-use)))
                   (plist-put info :partial_json nil)))
                ;; Reasoning content
                ((or "response.reasoning_summary_text.delta"
                     "response.reasoning.delta")
                 (when-let* ((delta (plist-get data :delta)))
                   (plist-put info :reasoning
                              (concat (plist-get info :reasoning) delta))))
                ((or "response.reasoning_summary_text.done"
                     "response.reasoning.done")
                 (plist-put info :reasoning-block t))
                ;; NOTE: backend tools are not supported in gptel yet, this
                ;; parsing is for the future
                ;; Web search completed (server-side tool)
                ("response.web_search_call.completed"
                 (push "\n[Web search completed]" content-strs))
                ;; Code interpreter output (server-side tool)
                ("response.code_interpreter_call.completed"
                 (when-let* ((item (plist-get data :item))
                             (results (plist-get item :results)))
                   (cl-loop
                    for result across results
                    if (equal (plist-get result :type) "logs")
                    do (push (format "\n```\n%s\n```" (plist-get result :logs))
                             content-strs))))
                ;; Response completed
                ("response.completed"
                 (when-let* ((tool-use (plist-get info :tool-use)))
                   ;; Inject tool calls into prompt data for continuation
                   ;; TODO(responses-api) Avoid re-encoding these tool calls,
                   ;; especially :arguments
                   (gptel--inject-prompt
                    (plist-get info :backend) (plist-get info :data)
                    (mapcar (lambda (tc)
                              (list :type "function_call"
                                    :call_id (plist-get tc :id)
                                    :name (plist-get tc :name)
                                    :arguments
                                    (gptel--json-encode (plist-get tc :args))))
                            tool-use)))
                 (when-let* ((resp (plist-get data :response)))
                   (plist-put info :stop-reason (plist-get resp :status))
                   (gptel--openai-responses-update-tokens
                    (plist-get resp :usage) info)))))))
      (error (goto-char (match-beginning 0))))
    (apply #'concat (nreverse content-strs))))

(cl-defmethod gptel--parse-response ((_backend gptel-openai-responses) response info)
  "Parse an OpenAI Responses API RESPONSE and return response text.
Mutate state INFO with response metadata."
  (let ((output-items (plist-get response :output))
        (content-strs) (tool-use) (tool-calls))
    ;; Store usage info
    (plist-put info :stop-reason (plist-get response :status))
    (gptel--openai-responses-update-tokens (plist-get response :usage) info)
    ;; Process output items
    (cl-loop
     for item across output-items
     for item-type = (plist-get item :type)
     do
     (pcase item-type
       ;; Text message output
       ("message"
        (when-let* ((content (plist-get item :content)))
          (cl-loop
           for part across content
           for part-type = (plist-get part :type)
           if (equal part-type "output_text")
           do (push (plist-get part :text) content-strs)
           else if (equal part-type "refusal")
           do (push (format "[Refused: %s]" (plist-get part :refusal))
                    content-strs))))
       ;; Function call from model (user-defined tools)
       ("function_call"
        (push item tool-calls)
        (push (list :id (plist-get item :call_id)
                    :name (plist-get item :name)
                    :args (ignore-errors
                            (gptel--json-read-string
                             (plist-get item :arguments))))
              tool-use))
       ;; Reasoning summary
       ("reasoning"
        (cl-loop with summary = (plist-get item :summary)
                 with content = (plist-get item :content)
                 for s across
                 (if (length= content 0) summary content)
                 collect (plist-get s :text) into reasoning
                 finally do
                 (plist-put info :reasoning (apply #'concat reasoning))))
       ;; Web search results (server-side tool)
       ("web_search_call"
        (when-let* ((status (plist-get item :status))
                    ((equal status "completed")))
          ;; Results are inline, just note that search was done
          (push "\n[Web search completed]" content-strs)))
       ;; Code interpreter output (server-side tool)
       ("code_interpreter_call"
        (when-let* ((status (plist-get item :status))
                    ((equal status "completed"))
                    (results (plist-get item :results)))
          (cl-loop
           for result across results
           for result-type = (plist-get result :type)
           if (equal result-type "logs")
           do (push (format "\n```\n%s\n```" (plist-get result :logs))
                    content-strs))))
       ;; File search results (server-side tool)
       ("file_search_call"
        (when-let* ((status (plist-get item :status))
                    ((equal status "completed"))
                    (results (plist-get item :results)))
          (push (format "\n[File search: %d results]" (length results))
                content-strs)))))
    ;; Store tool calls for user-defined function tools
    (when tool-use
      (plist-put info :tool-use (nreverse tool-use))
      ;; Inject into prompts for conversation continuity
      (gptel--inject-prompt
       (plist-get info :backend) (plist-get info :data)
       (nreverse tool-calls)))
    ;; Return concatenated content
    (when content-strs
      (apply #'concat (nreverse content-strs)))))

(cl-defmethod gptel--request-data ((backend gptel-openai-responses) prompts)
  "JSON encode PROMPTS for sending to OpenAI Responses API."
  (let ((prompts-plist
         `( :model ,(gptel--model-name gptel-model)
            :input ,(vconcat prompts)
            ;; Stateless: don't store responses server-side, don't use
            ;; previous_response_id. Each request contains full context.
            :store :json-false
            :stream ,(or gptel-stream :json-false)))
        (o-model-p (memq gptel-model '(o1 o1-preview o1-mini o3-mini o3 o4-mini))))
    ;; System message becomes instructions
    (when gptel--system-message
      (plist-put prompts-plist :instructions gptel--system-message))
    ;; Temperature
    (when (and gptel-temperature (not o-model-p)
               (not (eq (gptel-backend-key backend) 'oauth)))
      (plist-put prompts-plist :temperature gptel-temperature))
    ;; Max tokens
    (when (and gptel-max-tokens
               (not (eq (gptel-backend-key backend) 'oauth)))
      (plist-put prompts-plist :max_output_tokens gptel-max-tokens))
    (when gptel-use-tools
      (let ((tools-array
             (vconcat
              (when gptel-tools
                (gptel--parse-tools backend gptel-tools)))))
        (when (> (length tools-array) 0)
          (plist-put prompts-plist :tools tools-array))
        (when (eq gptel-use-tools 'force)
          (plist-put prompts-plist :tool_choice "required"))))
    ;; Structured output via text format
    (when gptel--schema
      (plist-put prompts-plist :text
                 (list :format
                       (list :type "json_schema"
                             :name (md5 (format "%s" (random)))
                             :schema (gptel--preprocess-schema
                                      (gptel--dispatch-schema-type gptel--schema))
                             :strict t))))
    ;; Merge request params
    (gptel--merge-plists
     prompts-plist
     gptel--request-params
     (gptel-backend-request-params gptel-backend)
     (gptel--model-request-params gptel-model))))

;; Helper functions for Responses API format conversion

(cl-defmethod gptel--parse-schema ((_backend gptel-openai-responses) schema)
  "Parse SCHEMA for Responses API structured output.
In Responses API, the schema format uses text.format instead of response_format."
  (list :type "json_schema"
        :name (md5 (format "%s" (random)))
        :schema (gptel--preprocess-schema
                 (gptel--dispatch-schema-type schema))
        :strict t))

(cl-defmethod gptel--parse-tools ((_backend gptel-openai-responses) tools)
  "Parse TOOLS and return a list of prompts.

TOOLS is a list of `gptel-tool' structs, which see.

_BACKEND is the LLM backend in use.  This is the default
implementation, used by OpenAI-compatible APIs and Ollama."
  (vconcat
   (mapcar
    (lambda (tool)
      (nconc
       (list
        :type "function"
        :name (gptel-tool-name tool)
        :description (gptel-tool-description tool))
       (if (gptel-tool-args tool)
           (list
            :parameters
            (list :type "object"
                  ;; gptel's tool args spec is close to the JSON schema, except
                  ;; that we use (:name "argname" ...)
                  ;; instead of  (:argname (...)), and
                  ;; (:optional t) for each arg instead of (:required [...])
                  ;; for all args at once.  Handle this difference by
                  ;; modifying a copy of the gptel tool arg spec.
                  :properties
                  (cl-loop
                   for arg in (gptel-tool-args tool)
                   for argspec = (copy-sequence arg)
                   for name = (plist-get arg :name) ;handled differently
                   for newname = (or (and (keywordp name) name)
                                     (make-symbol (concat ":" name)))
                   do                  ;ARGSPEC is ARG without unrecognized keys
                   (cl-remf argspec :name)
                   (cl-remf argspec :optional)
                   if (equal (plist-get arg :type) "object")
                   do (unless (plist-member argspec :required)
                        (plist-put argspec :required []))
                   (plist-put argspec :additionalProperties :json-false)
                   append (list newname argspec))
                  :required
                  (vconcat
                   (delq nil (mapcar
                              (lambda (arg) (and (not (plist-get arg :optional))
                                            (plist-get arg :name)))
                              (gptel-tool-args tool))))
                  :additionalProperties :json-false))
         (list :parameters (list :type "object" :properties nil)))))
    (ensure-list tools))))

(cl-defmethod gptel--inject-tool-call ((_backend gptel-openai-responses) data tool-call new-call)
  "Replace TOOL-CALL in query DATA with NEW-CALL.

BACKEND is the `gptel-backend'.  See the generic function documentation
for details.  This implementation handles the OpenAI Responses API."
  (if-let* ((input (plist-get data :input))
            (indexed-call
             (cl-loop for item across input
                      for i upfrom 0
                      if (and (equal (plist-get item :type) "function_call")
                              (equal (plist-get item :call_id) (plist-get tool-call :id)))
                      return (cons i item)))
            (index (car indexed-call))
            (call (cdr indexed-call)))
      (if (null new-call)               ;delete tool call if new-call is nil
          (plist-put data :input (vconcat (substring input 0 index)
                                          (substring input (1+ index))))
        (progn
          (when-let* ((args (plist-get new-call :args)))
            (plist-put call :arguments (gptel--json-encode args)))
          (when-let* ((name (plist-get new-call :name)))
            (plist-put call :name name))))
    (display-warning
     '(gptel tool-call)
     (format "Could not inject updated tool-call arguments for tool call %s, %s"
             (plist-get tool-call :name)
             (truncate-string-to-width (prin1-to-string new-call) 50 nil nil t)))))

(cl-defmethod gptel--parse-tool-results ((_backend gptel-openai-responses) tool-use)
  "Format TOOL-USE results for Responses API.
Returns prompts in Responses API format with function_call_output items."
  (mapcar
   (lambda (tool-call)
     (list
      :type "function_call_output"
      :call_id (plist-get tool-call :id)
      :output (plist-get tool-call :result)))
   tool-use))

(cl-defmethod gptel--inject-prompt
  ((_backend gptel-openai-responses) data new-prompt &optional position)
  "Inject NEW-PROMPT into existing prompts in query DATA.

NEW-PROMPT can be a single message or a list of messages.

If POSITION is
- nil, append NEW-PROMPT at the end of DATA
- a non-negative integer, insert it at that position in DATA.
- a negative integer, insert it there counting from the end."
  (when (keywordp (car-safe new-prompt)) ;Is new-prompt one or many?
    (setq new-prompt (list new-prompt)))
  (let ((prompts (plist-get data :input)))
    (pcase position
      ('nil (plist-put data :input (vconcat prompts new-prompt)))
      ((pred integerp)
       (when (< position 0) (setq position (+ (length prompts) position)))
       (plist-put data :input (vconcat (substring prompts 0 position)
                                       new-prompt
                                       (substring prompts position)))))))

(cl-defmethod gptel--parse-list ((backend gptel-openai-responses) prompt-list)
  (if (consp (car prompt-list))
      (let ((full-prompt))              ; Advanced format, list of lists
        (dolist (entry prompt-list)
          (pcase entry
            (`(prompt . ,msg)
             (push (list :role "user" :content (or (car-safe msg) msg)) full-prompt))
            (`(response . ,msg)
             (push (list :role "assistant" :content (or (car-safe msg) msg)) full-prompt))
            (`(tool . ,call)
             (unless (plist-get call :id)
               (plist-put call :id (gptel--openai-format-tool-id nil)))
             (push
              (list :type "function_call"
                    :call_id (plist-get call :id)
                    :name (plist-get call :name)
                    :arguments (decode-coding-string
                                (gptel--json-encode (plist-get call :args))
                                'utf-8 t))
              full-prompt)
             (push (car (gptel--parse-tool-results backend (list (cdr entry)))) full-prompt))))
        (nreverse full-prompt))
    (cl-loop for text in prompt-list    ; Simple format, list of strings
             for role = t then (not role)
             if text collect
             (list :role (if role "user" "assistant") :content text))))

(cl-defmethod gptel--parse-buffer ((backend gptel-openai-responses) &optional max-entries)
  (let ((prompts) (prev-pt (point)))
    (if (or gptel-mode gptel-track-response)
        (while (and (or (not max-entries) (>= max-entries 0))
                    (/= prev-pt (point-min))
                    (goto-char (previous-single-property-change
                                (point) 'gptel nil (point-min))))
          (pcase (get-char-property (point) 'gptel)
            ('response
             (when-let* ((content (gptel--trim-prefixes
                                   (buffer-substring-no-properties (point) prev-pt))))
               (push (list :role "assistant" :content content) prompts)))
            (`(tool . ,id)
             (save-excursion
               (condition-case nil
                   (let* ((tool-call (read (current-buffer)))
                          (name (plist-get tool-call :name))
                          (arguments (decode-coding-string
                                      (gptel--json-encode (plist-get tool-call :args))
                                      'utf-8 t)))
                     (setq id (gptel--openai-format-tool-id id))
                     (plist-put tool-call :id id)
                     (plist-put tool-call :result
                                (string-trim (buffer-substring-no-properties
                                              (point) prev-pt)))
                     (push (car (gptel--parse-tool-results backend (list tool-call)))
                           prompts)
                     (push (list :type "function_call"
                                 :call_id id
                                 :name name
                                 :arguments arguments)
                           prompts))
                 ((end-of-file invalid-read-syntax)
                  (message (format "Could not parse tool-call %s on line %s"
                                   id (line-number-at-pos (point))))))))
            ('ignore)
            ('nil
             (and max-entries (cl-decf max-entries))
             (if gptel-track-media
                 (when-let* ((content (gptel--openai-responses-parse-multipart
                                       (gptel--parse-media-links major-mode
                                                                 (point) prev-pt))))
                   (when (> (length content) 0)
                     (push (list :role "user" :content content) prompts)))
               (when-let* ((content (gptel--trim-prefixes (buffer-substring-no-properties
                                                           (point) prev-pt))))
                 (push (list :role "user" :content content) prompts)))))
          (setq prev-pt (point)))
      (let ((content (string-trim (buffer-substring-no-properties
                                   (point-min) (point-max)))))
        (push (list :role "user" :content content) prompts)))
    prompts))

(defun gptel--openai-responses-parse-multipart (parts)
  "Convert a multipart prompt PARTS to the OpenAI API format.

The input is an alist of the form
 ((:text \"some text\")
  (:media \"/path/to/media.png\" :mime \"image/png\")
  (:text \"More text\")).

The output is a vector of entries in a backend-appropriate
format."
  (cl-loop
   for part in parts
   for n upfrom 1
   with last = (length parts)
   for text = (plist-get part :text)
   for media = (plist-get part :media)
   if text do
   (and (or (= n 1) (= n last)) (setq text (gptel--trim-prefixes text)))
   and if text
   collect `(:type "input_text" :text ,text) into parts-array end
   else if media collect
   `(:type "input_image"
           :image_url ,(concat "data:" (plist-get part :mime)
                               ";base64," (gptel--base64-encode media)))
   into parts-array
   else if (plist-get part :textfile) collect
   `(:type "input_text"
           :text ,(with-temp-buffer
                    (gptel--insert-file-string (plist-get part :textfile))
                    (buffer-string)))
   into parts-array end and
   if (plist-get part :url)
   collect
   `(:type "input_image"
           :image_url ,(plist-get part :url))
   into parts-array
   finally return (vconcat parts-array)))

(cl-defmethod gptel--inject-media ((_backend gptel-openai-responses) prompts)
  "Wrap the first user prompt in PROMPTS with included media files.

Media files, if present, are placed in `gptel-context'."
  (when-let* ((media-list (gptel-context--collect-media)))
    (cl-callf (lambda (current)
                (vconcat
                 (gptel--openai-responses-parse-multipart media-list)
                 (cl-typecase current
                   (string `((:type "input_text" :text ,current)))
                   (vector current)
                   (t current))))
        (plist-get (car prompts) :content))))

;;;###autoload
(cl-defun gptel-make-openai-responses
    (name &key curl-args (models gptel--openai-models)
          stream key request-params
          (header
           (lambda (_info) (when-let* ((key (gptel--get-api-key)))
                        `(("Authorization" . ,(concat "Bearer " key))))))
          (host "api.openai.com")
          (protocol "https")
          (endpoint "/v1/responses"))
  "Register an OpenAI Responses API backend for gptel with NAME.

The Responses API is OpenAI's new API for agentic applications that
provides built-in tools like web search, code interpreter, and file
search.

Keyword arguments:

CURL-ARGS (optional) is a list of additional Curl arguments.

HOST (optional) is the API host, typically \"api.openai.com\".

MODELS is a list of available model names, as symbols.
Additionally, you can specify supported LLM capabilities like
vision or tool-use by appending a plist to the model with more
information, in the form

 (model-name . plist)

For a list of currently recognized plist keys, see
`gptel--openai-models'.

STREAM is a boolean to toggle streaming responses, defaults to
false.

PROTOCOL (optional) specifies the protocol, https by default.

ENDPOINT (optional) is the API endpoint for completions, defaults to
\"/v1/responses\".

HEADER (optional) is for additional headers to send with each
request.  It should be an alist or a function that returns an
alist, like:
 ((\"Content-Type\" . \"application/json\"))

KEY (optional) is a variable whose value is the API key, or
function that returns the key.  Set KEY to `oauth' to use ChatGPT
OAuth tokens from the OS keyring instead of an API key.  If no
tokens are stored, gptel requests them from OpenAI using device
code authorization.

REQUEST-PARAMS (optional) is a plist of additional HTTP request
parameters (as plist keys) and values supported by the API.  Use
these to set parameters that gptel does not provide user options
for.

Example:
-------

 (gptel-make-openai-responses
  \"OpenAI-Responses\"
  :stream t
  :models '((gpt-4o
             :capabilities (media tool-use json url responses-api)
             :mime-types (\"image/jpeg\" \"image/png\" \"image/gif\" \"image/webp\"))
            (gpt-4o-mini
             :capabilities (media tool-use json url responses-api)
             :mime-types (\"image/jpeg\" \"image/png\" \"image/gif\" \"image/webp\"))))"
  (declare (indent 1))
  (when (eq key 'oauth)
    (when (equal host "api.openai.com")
      (setq host "chatgpt.com"))
    (when (equal endpoint "/v1/responses")
      (setq endpoint "/backend-api/codex/responses"))
    (setq stream t)
    (setq header #'gptel--openai-chatgpt-header))
  (let ((backend (gptel--make-openai-responses
                  :curl-args curl-args
                  :name name
                  :host host
                  :header header
                  :key key
                  :models (gptel--process-models models)
                  :protocol protocol
                  :endpoint endpoint
                  :stream stream
                  :request-params request-params
                  :url (if protocol
                           (concat protocol "://" host endpoint)
                         (concat host endpoint)))))
    (prog1 backend
      (setf (alist-get name gptel--known-backends
                       nil nil #'equal)
            backend))))

(provide 'gptel-openai-responses)
;;; gptel-openai-responses.el ends here

;; Local Variables:
;; byte-compile-warnings: (not docstrings)
;; End:
