# Okta Golang Gin & Self-Hosted Login Page Example

> :grey_exclamation: The use of this Sample uses an SDK that requires usage of
> the Okta Identity Engine. This functionality is in general availability but is
> being gradually rolled out to customers. If you want to request to gain access
> to the Okta Identity Engine, please reach out to your account manager. If you
> do not have an account manager, please reach out to oie@okta.com for more
> information.

This Sample Application will show you the best practices for integrating
Authentication by embedding the Sign In Widget into your application. The Sign
In Widget is powered by [Okta's Identity
Engine](https://developer.okta.com/docs/concepts/ie-intro/) and will adjust
your user experience based on policies. Once integrated, you will be able to
utilize all the features of Okta's Sign In Widget in your application.

## Prerequisites

Before running this sample, you will need the following:

- [Go 1.13 +](https://go.dev/dl/)
- [The Okta CLI Tool](https://github.com/okta/okta-cli/#installation)
- An Okta Developer Account, create one using `okta register`, or configure an existing one with `okta login`

## Get the Code

Clone and configure this project from GitHub.

```bash
git clone https://github.com/oktadev/okta-go-gin-self-hosted-login-example.git

cd okta-go-gin-self-hosted-login-example
okta apps create web
```

Follow the instructions printed to the console and use the default values provided for redirect URIs. The Okta OIDC app will be created and configuration will be written to a `.okta.env` file.

> **Note**: Don't EVER commit `.okta.env` into source control. Add it to the `.gitignore` file.

You can also create an OIDC app via the Okta Developer Console GUI -> [oidc web application setup instructions][]

## Run the Example

```bash
go get # installs the dependencies
go run main.go
```

Now, navigate to http://localhost:8080 in your browser.

If you see a home page that prompts you to login, then things are working! Clicking the **Log in** button will redirect you to the applications custom sign-in page.

You can sign in with the same account that you created when signing up for your Developer Org, or you can use a known username and password from your Okta Directory.

> **Note**: If you are currently using the Okta Admin Console, you already have a Single Sign-On (SSO) session for your Org. You will be automatically logged into your application as the same user that is using the Developer Console. You may want to use an incognito tab to test the flow from a blank slate.

You can find more Golang sample in [this repository](https://github.com/okta/samples-golang)

[oidc web application setup instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application
