package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// member_since is a rendered relative phrase, not a timestamp — measured.
const accountBody = `{"username":"analyst","user_id":1234567,"member_since":"3344 days ago ",
  "pulse_count":3,"indicator_count":0,"subscriber_count":1,"follower_count":0,"award_count":0}`

func TestAuthCheckWithAValidKey(t *testing.T) {
	isolate(t, routes(map[string]string{"/users/me": accountBody}))
	t.Setenv("OTX_LOOKUP_API_KEY", "good-key")

	code, out, errOut := runCmd(t, "auth", "check")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, errOut)
	}
	for _, want := range []string{"valid", "analyst", "1234567", "10000 requests/hour", "3344 days ago"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "days ago \n") {
		t.Errorf("the trailing space upstream sends was not trimmed:\n%q", out)
	}
}

// A rejected key is the whole reason this command exists: every other command
// would keep working and keep printing "authenticated".
func TestAuthCheckWithARejectedKey(t *testing.T) {
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"detail":"Authentication required"}`))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "typo-key")

	code, out, _ := runCmd(t, "auth", "check")
	if code == exitOK {
		t.Error("a rejected key exited 0; a script would read that as working")
	}
	if !strings.Contains(out, "REJECTED") {
		t.Errorf("output does not say the key was rejected:\n%s", out)
	}
	if !strings.Contains(out, "typo") {
		t.Errorf("output does not suggest what to check:\n%s", out)
	}
}

// With no key there is nothing to ask upstream, and asking anyway would spend a
// request of a free service to be told what we already know.
func TestAuthCheckWithoutAKeySpendsNoRequest(t *testing.T) {
	requests := 0
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(accountBody))
	})

	code, out, _ := runCmd(t, "auth", "check")
	if code == exitOK {
		t.Error("no key exited 0")
	}
	if requests != 0 {
		t.Errorf("%d request(s) sent with no key configured", requests)
	}
	if !strings.Contains(out, "not configured") {
		t.Errorf("output does not state that no key is set:\n%s", out)
	}
	// It must also say what still works, so the reader does not think the tool
	// is unusable.
	if !strings.Contains(out, "still work") {
		t.Errorf("output does not say what works without a key:\n%s", out)
	}
	if !strings.Contains(out, "1000 requests/hour") {
		t.Errorf("output does not report the anonymous ceiling:\n%s", out)
	}
}

// An outage is not the same answer as a bad key, and must not be reported as one.
func TestAuthCheckDistinguishesAnOutageFromABadKey(t *testing.T) {
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"detail":"boom"}`))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "good-key")

	code, out, _ := runCmd(t, "auth", "check")
	if code != exitPartial {
		t.Errorf("exit = %d, want %d (an outage, not a rejection)", code, exitPartial)
	}
	if strings.Contains(out, "REJECTED") {
		t.Errorf("an outage was reported as a rejected key:\n%s", out)
	}
	if !strings.Contains(out, "UNKNOWN") {
		t.Errorf("output does not say the check was inconclusive:\n%s", out)
	}
	if !strings.Contains(out, "could not reach OTX") {
		t.Errorf("output does not name the real problem:\n%s", out)
	}
}

// The four states must stay distinct in JSON too, or a script collapses them.
func TestAuthCheckStatusIsFourValued(t *testing.T) {
	statusOf := func(t *testing.T, args ...string) string {
		t.Helper()
		_, out, _ := runCmd(t, args...)
		var st struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(out), &st); err != nil {
			t.Fatalf("not valid JSON: %v\n%s", err, out)
		}
		return st.Status
	}

	t.Run("valid", func(t *testing.T) {
		isolate(t, routes(map[string]string{"/users/me": accountBody}))
		t.Setenv("OTX_LOOKUP_API_KEY", "k")
		if got := statusOf(t, "auth", "check", "--json"); got != "valid" {
			t.Errorf("status = %q, want valid", got)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		isolate(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"detail":"Authentication required"}`))
		})
		t.Setenv("OTX_LOOKUP_API_KEY", "k")
		if got := statusOf(t, "auth", "check", "--json"); got != "rejected" {
			t.Errorf("status = %q, want rejected", got)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		isolate(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"detail":"boom"}`))
		})
		t.Setenv("OTX_LOOKUP_API_KEY", "k")
		if got := statusOf(t, "auth", "check", "--json"); got != "unreachable" {
			t.Errorf("status = %q, want unreachable", got)
		}
	})
	t.Run("absent", func(t *testing.T) {
		isolate(t, routes(nil))
		if got := statusOf(t, "auth", "check", "--json"); got != "absent" {
			t.Errorf("status = %q, want absent", got)
		}
	})
}

func TestAuthCheckJSON(t *testing.T) {
	isolate(t, routes(map[string]string{"/users/me": accountBody}))
	t.Setenv("OTX_LOOKUP_API_KEY", "good-key")

	code, out, errOut := runCmd(t, "auth", "check", "--json")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	var st struct {
		KeyConfigured bool     `json:"key_configured"`
		KeyValid      bool     `json:"key_valid"`
		Username      string   `json:"username"`
		RateCeiling   int      `json:"rate_ceiling"`
		Unlocks       []string `json:"unlocks"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if !st.KeyConfigured || !st.KeyValid {
		t.Errorf("status = %+v", st)
	}
	if st.Username != "analyst" || st.RateCeiling != 10000 {
		t.Errorf("status = %+v", st)
	}
	if len(st.Unlocks) == 0 {
		t.Error("the JSON form does not say what a key unlocks")
	}
}

// The key itself must never appear in the output of a command whose whole job
// is to talk about the key.
func TestAuthCheckNeverPrintsTheKey(t *testing.T) {
	isolate(t, routes(map[string]string{"/users/me": accountBody}))
	t.Setenv("OTX_LOOKUP_API_KEY", "super-secret-key-value")

	for _, args := range [][]string{{"auth", "check"}, {"auth", "check", "--json"}} {
		_, out, errOut := runCmd(t, args...)
		if strings.Contains(out, "super-secret") || strings.Contains(errOut, "super-secret") {
			t.Errorf("%v printed the key", args)
		}
	}
}

// --anonymous makes the check report on the anonymous case rather than on the
// configured key, and says so.
func TestAuthCheckHonoursAnonymous(t *testing.T) {
	requests := 0
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(accountBody))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "good-key")

	code, out, _ := runCmd(t, "auth", "check", "--anonymous")
	if code == exitOK {
		t.Error("--anonymous reported a working key")
	}
	if requests != 0 {
		t.Errorf("%d request(s) sent under --anonymous", requests)
	}
	if !strings.Contains(out, "--anonymous") {
		t.Errorf("output does not explain why no key was used:\n%s", out)
	}
}

func TestAuthRejectsUnknownSubcommand(t *testing.T) {
	isolate(t, routes(nil))
	for _, args := range [][]string{{"auth"}, {"auth", "login"}, {"auth", "check", "extra"}} {
		if code, _, _ := runCmd(t, args...); code != exitError {
			t.Errorf("%v: exit = %d, want %d", args, code, exitError)
		}
	}
}
