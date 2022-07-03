package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	idx "github.com/okta/okta-idx-golang"
)

// IndexHandler serves the index.html page
func (s *Server) IndexHandler(c *gin.Context) {
	log.Println("Loading main page")

	errorMsg := ""

	profile, err := s.getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}

	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the index.gohtml template
		"index.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": s.isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func (s *Server) LoginHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	lr, err := s.idxClient.InitLogin(c)
	if err != nil {
		log.Fatalf("error idx client init login: %+v", err)
	}
	s.cache.Set("loginResponse", lr, time.Minute*5)

	key, ok := c.GetQuery("lang")

	if !ok {
		log.Println("Url Param 'lang' is missing")
		key = "en" // set this as default
	}

	issuerURL := s.idxClient.Config().Okta.IDX.Issuer
	issuerParts, err := url.Parse(issuerURL)
	if err != nil {
		log.Fatalf("error: %s\n", err.Error())
	}
	baseUrl := issuerParts.Scheme + "://" + issuerParts.Hostname()
	// set up our data structure with all the config details and the interact
	// handle with bootstrapping the widget.
	s.LoginData = LoginData{
		IsAuthenticated:     lr.IsAuthenticated(),
		BaseUrl:             baseUrl,
		RedirectURI:         s.idxClient.Config().Okta.IDX.RedirectURI,
		ClientId:            s.idxClient.Config().Okta.IDX.ClientID,
		Issuer:              s.idxClient.Config().Okta.IDX.Issuer,
		State:               lr.Context().State,
		CodeChallenge:       lr.Context().CodeChallenge,
		CodeChallengeMethod: lr.Context().CodeChallengeMethod,
		InteractionHandle:   lr.Context().InteractionHandle.InteractionHandle,
		Lang:                key,
	}

	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the login.gohtml template
		"login.gohtml",
		// Pass the data that the page uses
		s.LoginData,
	)
}

func (s *Server) LogoutHandler(c *gin.Context) {
	// revoke the oauth2 access token it exists in the session API
	// side before deleting session info.
	logoutURL := "/"
	if session, err := s.sessionStore.Get(c.Request, SESSION_STORE_NAME); err == nil {
		if accessToken, found := session.Values["access_token"]; found {
			if err := s.idxClient.RevokeToken(c.Request.Context(), accessToken.(string)); err != nil {
				fmt.Printf("revoke error: %+v\n", err)
			}
		}

		if idToken, found := session.Values["id_token"]; found {
			// redirect must match one of the "Sign-out redirect URIs"
			// defined on the Okta application.
			redirect, _ := url.Parse(s.idxClient.Config().Okta.IDX.RedirectURI)
			redirect.Path = "/"
			params := url.Values{
				"id_token_hint":            {idToken.(string)},
				"post_logout_redirect_uri": {redirect.String()},
			}
			// server must redirect out to the Okta API to perform a proper logout
			logoutURL = s.oAuthEndPoint(fmt.Sprintf("logout?%s", params.Encode()))
		}

		delete(session.Values, "id_token")
		delete(session.Values, "access_token")
		session.Save(c.Request, c.Writer)
	}

	// reset the idx context
	s.cache.Flush()
	c.Redirect(http.StatusFound, logoutURL)

}

func (s *Server) ProfileHandler(c *gin.Context) {
	errorMsg := ""

	profile, err := s.getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the profile.gohtml template
		"profile.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": s.isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func (s *Server) getProfileData(r *http.Request) (map[string]string, error) {
	m := make(map[string]string)

	session, err := s.sessionStore.Get(r, SESSION_STORE_NAME)

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m, nil
	}
	// the endpoint which is to be called for profile data
	reqUrl := s.oAuthEndPoint("userinfo")

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return m, err
	}

	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return m, err
	}

	json.Unmarshal(body, &m)

	return m, nil
}

func (s *Server) AuthCodeCallbackHandler(c *gin.Context) {

	// Check if interaction_required error is returned
	if c.Query("error") == "interaction_required" {
		c.Header("Cache-Control", "no-cache")

		s.LoginData.IsAuthenticated = s.isAuthenticated(c.Request)
		c.HTML(http.StatusOK, "login.gohtml", s.LoginData)
		return
	}

	clr, found := s.cache.Get("loginResponse")
	if !found {
		log.Fatalln("loginResponse is not cached")
	}
	// once again populate loginResponse for this handler from the cache.
	lr := clr.(*idx.LoginResponse)
	lr, err := lr.WhereAmI(c.Request.Context())
	if err != nil {
		log.Fatalf("LoginResponse WhereAmI error: %s", err.Error())
	}

	// Check the state that was returned in the query string is the same as the above state
	// Match if the state token from the handler matches the one we got from loginResponse before asking for id token
	if c.Query("state") != lr.Context().State {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("The state was not as expected"))
		return
	}

	// inbound magic link otp.
	// TBD why is the otp in the request? Polling here to get the otp from the client side.
	if c.Query("otp") != "" {
		c.Header("Cache-Control", "no-cache")

		s.LoginData.OTP = c.Query("otp")
		c.HTML(http.StatusOK, "login.gohtml", s.LoginData)
		return
	}

	// Check that the interaction_code was provided
	if c.Query("interaction_code") == "" {
		fmt.Fprintln(c.Writer, "The interaction_code was not returned or is not accessible")
		return
	}

	// destination for the id and access token.
	session, err := s.sessionStore.Get(c.Request, SESSION_STORE_NAME)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	// magic of getting everything like interaction code, and 1.request context (why) 2.lr has all our data.
	// Exchange it for tokens.
	accessToken, err := s.idxClient.RedeemInteractionCode(c.Request.Context(), lr.Context(), c.Query("interaction_code"))
	if err != nil {
		log.Fatalf("access token error: %+v\n", err)
	}
	session.Values["id_token"] = accessToken.IDToken
	session.Values["access_token"] = accessToken.AccessToken
	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/")

}

//Checks if id token is in it or not and returns true/false
func (s *Server) isAuthenticated(r *http.Request) bool {
	session, err := s.sessionStore.Get(r, SESSION_STORE_NAME)

	if err != nil {
		return false
	}
	_, found := session.Values["id_token"]
	return found
}

func (s *Server) oAuthEndPoint(operation string) string {
	var endPoint string
	issuer := s.idxClient.Config().Okta.IDX.Issuer
	if strings.Contains(issuer, "oauth2") {
		endPoint = fmt.Sprintf("%s/v1/%s", issuer, operation)
	} else {
		endPoint = fmt.Sprintf("%s/oauth2/v1/%s", issuer, operation)
	}
	return endPoint
}
