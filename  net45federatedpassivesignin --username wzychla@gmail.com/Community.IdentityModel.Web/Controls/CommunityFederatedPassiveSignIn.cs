using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Xml;

namespace Community.IdentityModel.Web.Controls
{
    /// <summary>
    /// Substitute of wif:FederatedPassiveSignIn control
    /// </summary>
    public class CommunityFederatedPassiveSignIn :
        WebControl,
        IPostBackDataHandler
    {
        #region Internal token receiver
        /// <summary>
        /// TokenReceiver
        /// </summary>
        internal class FederationPassiveTokenReceiver
        {
            FederationConfiguration _serviceConfiguration;

            public FederationPassiveTokenReceiver( FederationConfiguration serviceConfiguration )
            {
                if ( serviceConfiguration == null )
                    throw new ArgumentNullException();

                this._serviceConfiguration = serviceConfiguration;
            }

            public TimeSpan ConfiguredSessionTokenLifeTime
            {
                get
                {
                    TimeSpan result = SessionSecurityTokenHandler.DefaultTokenLifetime;
                    if ( this._serviceConfiguration.IdentityConfiguration.SecurityTokenHandlers != null )
                    {
                        SessionSecurityTokenHandler sessionSecurityTokenHandler = this._serviceConfiguration.IdentityConfiguration.SecurityTokenHandlers[typeof( SessionSecurityToken )] as SessionSecurityTokenHandler;
                        if ( sessionSecurityTokenHandler != null )
                        {
                            result = sessionSecurityTokenHandler.TokenLifetime;
                        }
                    }
                    return result;
                }
            }

            public ClaimsPrincipal AuthenticateToken( SecurityToken token, bool ensureBearerToken, string endpointUri )
            {
                if ( token == null )
                    throw new ArgumentNullException();

                if ( ensureBearerToken && token.SecurityKeys != null && token.SecurityKeys.Count != 0 )
                    throw new SecurityTokenException();

                var identity = this._serviceConfiguration.IdentityConfiguration.SecurityTokenHandlers.ValidateToken( token ).FirstOrDefault();
                return this._serviceConfiguration.IdentityConfiguration.ClaimsAuthenticationManager.Authenticate( endpointUri, new ClaimsPrincipal( identity ) );
            }

            public void ComputeSessionTokenLifeTime( SecurityToken securityToken, out DateTime validFrom, out DateTime validTo )
            {
                TimeSpan configuredSessionTokenLifeTime = this.ConfiguredSessionTokenLifeTime;
                validFrom = DateTime.UtcNow;
                validTo = validFrom.Add( configuredSessionTokenLifeTime );
                if ( securityToken != null )
                {
                    if ( validFrom < securityToken.ValidFrom )
                    {
                        validFrom = securityToken.ValidFrom;
                    }
                    if ( validTo > securityToken.ValidTo )
                    {
                        validTo = securityToken.ValidTo;
                    }
                }
            }

            public SecurityToken ReadToken( string tokenXml )
            {
                if ( string.IsNullOrEmpty( tokenXml ) )
                    throw new ArgumentNullException();

                SecurityToken result;
                try
                {
                    using ( XmlTextReader xmlDictionaryReader = new XmlTextReader( tokenXml, XmlNodeType.Element, null ) )
                    {
                        xmlDictionaryReader.MoveToContent();

                        SecurityToken securityToken = this.ReadToken( xmlDictionaryReader );
                        if ( securityToken == null )
                            throw new SecurityTokenException();

                        result = securityToken;
                    }
                }
                catch ( EncryptedTokenDecryptionFailedException innerException )
                {
                    string text;
                    if ( this._serviceConfiguration.ServiceCertificate == null )
                    {
                        text = "No certificate found in configuration";
                    }
                    else
                    {
                        text = "[Thumbprint] " + this._serviceConfiguration.ServiceCertificate.Thumbprint;
                    }
                    throw new SecurityTokenException( text, innerException );
                }

                return result;
            }

            private SecurityToken ReadToken( XmlReader reader )
            {
                SecurityTokenHandlerCollection securityTokenHandlers = this._serviceConfiguration.IdentityConfiguration.SecurityTokenHandlers;
                if ( securityTokenHandlers.CanReadToken( reader ) )
                {
                    return securityTokenHandlers.ReadToken( reader );
                }
                return null;
            }

        }

        #endregion

        #region Events

        private EventHandlerList events = new EventHandlerList();

        private static readonly object EventSecurityTokenReceived = new object();
        private static readonly object EventSecurityTokenValidated = new object();
        private static readonly object EventSessionSecurityTokenCreated = new object();
        private static readonly object EventSignedIn = new object();

        protected virtual void OnSecurityTokenReceived( SecurityTokenReceivedEventArgs e )
        {
            EventHandler<SecurityTokenReceivedEventArgs> eventHandler = (EventHandler<SecurityTokenReceivedEventArgs>)this.events[EventSecurityTokenReceived];
            if ( eventHandler != null )
            {
                eventHandler( this, e );
            }
        }

        protected virtual void OnSecurityTokenValidated( SecurityTokenValidatedEventArgs e )
        {
            EventHandler<SecurityTokenValidatedEventArgs> eventHandler = (EventHandler<SecurityTokenValidatedEventArgs>)this.events[EventSecurityTokenValidated];
            if ( eventHandler != null )
            {
                eventHandler( this, e );
            }
        }

        protected virtual void OnSessionSecurityTokenCreated( SessionSecurityTokenCreatedEventArgs e )
        {
            EventHandler<SessionSecurityTokenCreatedEventArgs> eventHandler = (EventHandler<SessionSecurityTokenCreatedEventArgs>)this.events[EventSessionSecurityTokenCreated];
            if ( eventHandler != null )
            {
                eventHandler( this, e );
            }
        }

        protected virtual void OnSignedIn( EventArgs e )
        {
            EventHandler eventHandler = (EventHandler)this.events[EventSignedIn];
            if ( eventHandler != null )
            {
                eventHandler( this, e );
            }
        }

        public event EventHandler<SecurityTokenReceivedEventArgs> SecurityTokenReceived
        {
            add
            {
                this.events.AddHandler( EventSecurityTokenReceived, value );
            }
            remove
            {
                this.events.RemoveHandler( EventSecurityTokenReceived, value );
            }
        }

        public event EventHandler<SecurityTokenValidatedEventArgs> SecurityTokenValidated
        {
            add
            {
                this.events.AddHandler( EventSecurityTokenValidated, value );
            }
            remove
            {
                this.events.RemoveHandler( EventSecurityTokenValidated, value );
            }
        }

        public event EventHandler<SessionSecurityTokenCreatedEventArgs> SessionSecurityTokenCreated
        {
            add
            {
                this.events.AddHandler( EventSessionSecurityTokenCreated, value );
            }
            remove
            {
                this.events.RemoveHandler( EventSessionSecurityTokenCreated, value );
            }
        }

        public event EventHandler SignedIn
        {
            add
            {
                this.events.AddHandler( EventSignedIn, value );
            }
            remove
            {
                this.events.RemoveHandler( EventSignedIn, value );
            }
        }

        #endregion

        #region Properties

        private WSFederationAuthenticationModule _federationAuthenticationModule;
        private WSFederationAuthenticationModule FederationAuthenticationModule
        {
            get
            {
                if ( _federationAuthenticationModule == null )
                {
                    _federationAuthenticationModule = new WSFederationAuthenticationModule();
                    _federationAuthenticationModule.FederationConfiguration = FederatedAuthentication.FederationConfiguration;

                    _federationAuthenticationModule.Issuer = this.Issuer;
                    _federationAuthenticationModule.Realm = this.Realm;
                }

                return _federationAuthenticationModule;
            }
        }

        public bool AutoSignIn { get; set; }

        public string Realm { get; set; }
        public string Issuer { get; set; }
        public string TitleText { get; set; }

        public string ErrorText { get; set; }

        #endregion

        #region Infrastructure

        public CommunityFederatedPassiveSignIn()
        {
            this.PreRender += CommunityFederatedPassiveSignIn_PreRender;
        }

        void CommunityFederatedPassiveSignIn_PreRender( object sender, EventArgs e )
        {
            string wctx = this.Context.Request.Form["wctx"];
            if ( !string.IsNullOrEmpty( wctx ) )
            {
                var context = HttpUtility.ParseQueryString( wctx );

                string clientid = context["id"];
                string returnUrl = context["ru"];

                if ( clientid == this.ClientID &&
                     this.FederationAuthenticationModule.CanReadSignInResponse( new HttpRequestWrapper( this.Context.Request ) )
                    )
                {
                    if ( string.IsNullOrEmpty( returnUrl ) )
                        returnUrl = "/";

                    if ( this.HandleResponseMessage() )
                        this.Context.Response.Redirect( returnUrl );
                }
            }

            if ( this.AutoSignIn )
                this.RedirectToIdentityProvider();
        }

        protected override void RenderContents( System.Web.UI.HtmlTextWriter writer )
        {
            writer.WriteBeginTag( "table" );
            writer.WriteAttribute( "cellspacing", "0" );
            writer.WriteAttribute( "cellpadding", "1" );
            writer.Write( HtmlTextWriter.TagRightChar );

            // button
            writer.WriteFullBeginTag( "tr" ); writer.WriteFullBeginTag( "td" );
            writer.WriteBeginTag( "input" );
            writer.WriteAttribute( "type", "submit" );
            writer.WriteAttribute( "name", this.ClientID );
            writer.WriteAttribute( "value", !string.IsNullOrEmpty( this.TitleText ) ? this.TitleText : this.ID.ToString() );
            writer.Write( HtmlTextWriter.TagRightChar );
            writer.WriteEndTag( "input" );
            writer.WriteEndTag( "td" ); writer.WriteEndTag( "tr" );

            // error
            if ( !string.IsNullOrEmpty( this.ErrorText ) )
            {
                writer.WriteFullBeginTag( "tr" ); writer.WriteFullBeginTag( "td" );
                writer.Write( this.ErrorText );
                writer.WriteEndTag( "td" ); writer.WriteEndTag( "tr" );
            }

            writer.WriteEndTag( "table" );
        }

        #endregion

        #region IPostBackDataHandler Members

        public bool LoadPostData(
            string postDataKey,
            NameValueCollection postCollection )
        {
            string value = postCollection[postDataKey];

            if ( value == this.ClientID )
                RedirectToIdentityProvider();

            return false;
        }

        public void RaisePostDataChangedEvent()
        {

        }

        #endregion

        #region Business logic

        private void RedirectToIdentityProvider()
        {
            var signInRequest = FederationAuthenticationModule.CreateSignInRequest( this.ClientID, this.Context.Request["ReturnUrl"], false );
            var redirectUri = signInRequest.RequestUrl;

            if ( !string.IsNullOrEmpty( redirectUri ) )
                this.Context.Response.Redirect( redirectUri );
        }

        private bool HandleResponseMessage()
        {
            try
            {
                var responseMessage = FederationAuthenticationModule.GetSignInResponseMessage( new HttpRequestWrapper( this.Context.Request ) );
                if ( responseMessage != null )
                {
                    string xmlTokenFromMessage = this.FederationAuthenticationModule.GetXmlTokenFromMessage( responseMessage, null );

                    FederationConfiguration serviceConfiguration = this.FederationAuthenticationModule.FederationConfiguration;
                    //ServiceConfiguration serviceConfiguration       = CUFSSecurityTokenServiceConfiguration.Current;
                    FederationPassiveTokenReceiver tokenReceiver = new FederationPassiveTokenReceiver( serviceConfiguration );
                    SecurityToken securityToken = tokenReceiver.ReadToken( xmlTokenFromMessage );

                    SecurityTokenReceivedEventArgs securityTokenReceivedEventArgs = new SecurityTokenReceivedEventArgs( securityToken );
                    this.OnSecurityTokenReceived( securityTokenReceivedEventArgs );

                    if ( !securityTokenReceivedEventArgs.Cancel )
                    {
                        ClaimsPrincipal claimsPrincipal = tokenReceiver.AuthenticateToken( securityTokenReceivedEventArgs.SecurityToken, true, HttpContext.Current.Request.RawUrl );
                        if ( claimsPrincipal != null )
                        {
                            SecurityTokenValidatedEventArgs securityTokenValidatedEventArgs = new SecurityTokenValidatedEventArgs( claimsPrincipal );
                            this.OnSecurityTokenValidated( securityTokenValidatedEventArgs );
                            if ( !securityTokenValidatedEventArgs.Cancel )
                            {
                                SessionAuthenticationModule current = FederatedAuthentication.SessionAuthenticationModule;

                                DateTime validFrom;
                                DateTime validTo;

                                tokenReceiver.ComputeSessionTokenLifeTime( securityTokenReceivedEventArgs.SecurityToken, out validFrom, out validTo );
                                SessionSecurityToken sessionToken = current.CreateSessionSecurityToken( securityTokenValidatedEventArgs.ClaimsPrincipal, this.GetSessionTokenContext(), validFrom, validTo, false );

                                SessionSecurityTokenCreatedEventArgs sessionSecurityTokenCreatedEventArgs = new SessionSecurityTokenCreatedEventArgs( sessionToken );
                                sessionSecurityTokenCreatedEventArgs.WriteSessionCookie = true;

                                this.OnSessionSecurityTokenCreated( sessionSecurityTokenCreatedEventArgs );

                                this.FederationAuthenticationModule.SetPrincipalAndWriteSessionToken( sessionSecurityTokenCreatedEventArgs.SessionToken, sessionSecurityTokenCreatedEventArgs.WriteSessionCookie );

                                this.OnSignedIn( EventArgs.Empty );

                                return true;
                            }
                        }
                    }
                }

                return false;
            }
            catch ( Exception ex )
            {
                this.ErrorText = ex.Message;
                return false;
            }
        }

        protected string GetSessionTokenContext()
        {
            return "(" + typeof( WSFederationAuthenticationModule ).Name + ")" + WSFederationAuthenticationModule.GetFederationPassiveSignOutUrl( this.Issuer, string.Empty, string.Empty );
        }

        #endregion
    }
}