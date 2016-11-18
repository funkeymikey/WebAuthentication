using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Security.Principal;
using System.Text;
using System.Web;

namespace WebAuthentication
{

	public class BasicAuthenticationModule : IHttpModule
	{
		public const string HttpAuthorizationHeader = "Authorization";  // HTTP1.1 Authorization header 
		public const string HttpBasicSchemeName = "Basic"; // HTTP1.1 Basic Challenge Scheme Name 
		public const char HttpCredentialSeparator = ':'; // HTTP1.1 Credential username and password separator 
		public const int HttpNotAuthorizedStatusCode = 401; // HTTP1.1 Not authorized response status code 
		public const string HttpWWWAuthenticateHeader = "WWW-Authenticate"; // HTTP1.1 Basic Challenge Scheme Name 
	//	public const string Realm = "demo"; // HTTP.1.1 Basic Challenge Realm 

		public void Init(HttpApplication context)
		{
			// Subscribe to the authenticate event to perform the authentication
			context.AuthenticateRequest += new EventHandler(this.AuthenticateUser);

			// Subscribe to the EndRequest event to issue the challenge if necessary
			context.EndRequest += new EventHandler(this.IssueAuthenticationChallenge);
		}

		public void Dispose()
		{
		}


		public void AuthenticateUser(object source, EventArgs e)
		{
			HttpApplication application = (HttpApplication)source;
			HttpContext context = application.Context;
			
			//if we're on the excluded site, say we're good
			if (context.Request.Url.Host == ConfigurationManager.AppSettings["ExcludedSecurityHost"])
			{
				context.User = new GenericPrincipal(new GenericIdentity("user"), null);
				return;
			}

			string userName = null;
			string password = null;
			string authorizationHeader = context.Request.Headers[HttpAuthorizationHeader];

			// Extract the basic authentication credentials from the request
			if (!this.ExtractBasicCredentials(authorizationHeader, ref userName, ref password))
				return;

			// Validate the user credentials
			if (!this.ValidateCredentials(userName, password))
				return;

			// Create the user principal and associate it with the request
			context.User = new GenericPrincipal(new GenericIdentity(userName), null);
		}

		public void IssueAuthenticationChallenge(object source, EventArgs e)
		{
			HttpApplication application = (HttpApplication)source;
			HttpContext context = application.Context;

			// Issue a basic challenge if necessary
			if (context.Response.StatusCode == HttpNotAuthorizedStatusCode)
			{
				context.Response.AddHeader(HttpWWWAuthenticateHeader, "Basic");
			}
		}

		protected virtual bool ValidateCredentials(string userName, string password)
		{
			//if either of these isn't specified, false
			if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
				return false;

			if (userName.Equals("guest", StringComparison.InvariantCultureIgnoreCase)){

				//check the app settings for a guest password
				string guestPass = ConfigurationManager.AppSettings["GuestPassword"];

				if (guestPass == password)
					return true;

				else return false;
			}

			NameValueCollection userCreds = ConfigurationManager.GetSection("webAuth") as NameValueCollection;

			//if the section isn't specified, false
			if (userCreds == null)
				return false;

			//if the section is empty, false
			if (!userCreds.HasKeys())
				return false;

			//get the pass out of the config section
			string credPass = userCreds[userName];

			//if the username wasn't found in config, false
			if (string.IsNullOrWhiteSpace(credPass))
				return false;

			//only succeed if passwords match
			if (password.Equals(credPass))
				return true;

			return false;
		}

		protected virtual bool ExtractBasicCredentials(string authorizationHeader, ref string username, ref string password)
		{
			if (string.IsNullOrWhiteSpace(authorizationHeader))
				return false;

			string verifiedAuthorizationHeader = authorizationHeader.Trim();
			if (verifiedAuthorizationHeader.IndexOf(HttpBasicSchemeName) != 0)
				return false;

			// get the credential payload 
			verifiedAuthorizationHeader = verifiedAuthorizationHeader.Substring(HttpBasicSchemeName.Length, verifiedAuthorizationHeader.Length - HttpBasicSchemeName.Length).Trim();
			// decode the base 64 encoded credential payload 
			byte[] credentialBase64DecodedArray = Convert.FromBase64String(verifiedAuthorizationHeader);
			UTF8Encoding encoding = new UTF8Encoding();
			string decodedAuthorizationHeader = encoding.GetString(credentialBase64DecodedArray, 0, credentialBase64DecodedArray.Length);

			// get the username, password, and realm 
			int separatorPosition = decodedAuthorizationHeader.IndexOf(HttpCredentialSeparator);

			if (separatorPosition <= 0)
				return false;
			username = decodedAuthorizationHeader.Substring(0, separatorPosition).Trim();
			password = decodedAuthorizationHeader.Substring(separatorPosition + 1, (decodedAuthorizationHeader.Length - separatorPosition - 1)).Trim();

			if (username.Equals(string.Empty) || password.Equals(string.Empty))
				return false;

			return true;
		}

	}
}