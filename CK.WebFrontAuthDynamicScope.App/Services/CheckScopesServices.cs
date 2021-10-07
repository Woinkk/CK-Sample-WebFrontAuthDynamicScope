using CK.Auth;
using CK.Core;
using CK.DB.Auth.AuthScope;
using CK.SqlServer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace CK.WebFrontAuthDynamicScope.App.Services
{
    public class CheckScopesServices : IAutoService
    {
        readonly IHttpClientFactory _httpClientFactory;
        readonly CK.DB.User.UserFacebook.AuthScope.Package _facebookScope;
        readonly CK.DB.User.UserGoogle.AuthScope.Package _googleScope;

        public CheckScopesServices( IHttpClientFactory httpClientFactory, CK.DB.User.UserFacebook.AuthScope.Package facebookScope, CK.DB.User.UserGoogle.AuthScope.Package googleScope )
        {
            _httpClientFactory = httpClientFactory;
            _facebookScope = facebookScope;
            _googleScope = googleScope;
        }

        // For the provider Facebook, check which scopes the user has accepted or rejected.
        public async Task CheckAndUpdateFacebookScopesAsync( IActivityMonitor m, HttpContext c, IAuthenticationInfo current, string? accessToken )
        {
            using( var ctx = new SqlStandardCallContext() )
            using( HttpClient client = _httpClientFactory.CreateClient() )
            {
                try
                {
                    // Setup the http client with an access token then make a request to Facebook graph api to check scopes status.
                    // Documentation about the request: https://developers.facebook.com/docs/facebook-login/handling-declined-permissions
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue( "Bearer", accessToken );
                    HttpResponseMessage httpResponse = await client.GetAsync( "https://graph.facebook.com/me/permissions" );

                    // Deserialize the response from the previous api call.
                    Stream streamResponse = await httpResponse.Content.ReadAsStreamAsync();
                    FacebookScopeList scopeList = await JsonSerializer.DeserializeAsync<FacebookScopeList>( streamResponse );

                    // Get the AuthScopeSet of the current user.
                    AuthScopeSet? scopeSet = await _facebookScope.ReadScopeSetAsync( ctx, current.ActualUser.UserId );

                    // If the AuthScopeSet is empty then we fill it with the default scope set for Facebook.
                    if( scopeSet.Count <= 0 )
                    {
                        int scopeSetId = scopeSet.ScopeSetId;
                        scopeSet = await _facebookScope.ReadDefaultScopeSetAsync( ctx );
                        scopeSet.ScopeSetId = scopeSetId;
                    }

                    // For each scopes check if the scope is accepted or rejected by the user and update is AuthScopeSet.
                    foreach( FacebookScope scope in scopeList.data )
                    {
                        if( scopeSet.CheckStatus( ScopeWARStatus.Waiting, scope.permission ) )
                        {
                            if( scope.status == "granted" )
                                scopeSet.Add( new AuthScopeItem( scope.permission, ScopeWARStatus.Accepted ) );
                            else
                                scopeSet.Add( new AuthScopeItem( scope.permission, ScopeWARStatus.Rejected ) );
                        }
                    }

                    // Update database with the updated AuthScopeSet.
                    await _facebookScope.AuthScopeSetTable.AddOrUpdateScopesAsync( ctx, current.ActualUser.UserId, scopeSet );
                }
                catch( HttpRequestException e )
                {
                    Console.WriteLine( "\nException Caught!" );
                    Console.WriteLine( "Message :{0} ", e.Message );
                }
            }
        }

        // For the provider Google, check which scopes the user has accepted or rejected.
        public async Task CheckAndUpdateGoogleScopesAsync( IActivityMonitor m, HttpContext c, IAuthenticationInfo current, string? accessToken )
        {
            using( var ctx = new SqlStandardCallContext() )
            using( HttpClient client = _httpClientFactory.CreateClient() )
            {
                try
                {
                    if (accessToken != null)
                    {
                        // Make request to get some user info from the current access token.
                        HttpResponseMessage httpResponse = await client.GetAsync( $"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={accessToken}" );

                        // Deserialize the response from the previous api call.
                        Stream streamResponse = await httpResponse.Content.ReadAsStreamAsync();
                        GoogleJsonResponse googleResponse = await JsonSerializer.DeserializeAsync<GoogleJsonResponse>( streamResponse );

                        // Get the AuthScopeSet of the current user.
                        AuthScopeSet? scopeSet = await _googleScope.ReadScopeSetAsync( ctx, current.ActualUser.UserId );

                        // If the AuthScopeSet is empty then we fill it with the default scope set for Google.
                        if( scopeSet.Count <= 0 )
                        {
                            int scopeSetId = scopeSet.ScopeSetId;
                            scopeSet = await _googleScope.ReadDefaultScopeSetAsync( ctx );
                            scopeSet.ScopeSetId = scopeSetId;
                        }

                        // Scopes are returned in the form of a string, each scopes are separated by whitespaces.
                        string[] googleScopesArray = googleResponse.scope.Split( ' ' );

                        // For each scopes check if the scope is accepted or rejected by the user and update is AuthScopeSet.
                        foreach( string scope in googleScopesArray )
                        {
                            if( scopeSet.CheckStatus( ScopeWARStatus.Waiting, scope ) )
                            {
                                AuthScopeItem authScopeItem = new AuthScopeItem( scope, ScopeWARStatus.Accepted );
                                scopeSet.Add( authScopeItem );
                            }
                        }

                        // Google only return scopes accepted by the user.
                        // For each remaining scopes with the waiting status we put them as rejected.
                        scopeSet?.Scopes.Where( s => s.Status == ScopeWARStatus.Waiting )
                            .Select( s => s.ScopeName )
                            .ToList()
                            .ForEach( scope => scopeSet.Add( new AuthScopeItem( scope, ScopeWARStatus.Rejected ) ) );

                        // Update database with the updated AuthScopeSet.
                        await _googleScope.AuthScopeSetTable.AddOrUpdateScopesAsync( ctx, current.ActualUser.UserId, scopeSet );
                    } else
                    {
                        // Get the AuthScopeSet of the current user.
                        AuthScopeSet? scopeSet = await _googleScope.ReadScopeSetAsync( ctx, current.ActualUser.UserId );

                        // If the AuthScopeSet is empty then we fill it with the default scope set for Google.
                        if( scopeSet.Count <= 0 )
                        {
                            int scopeSetId = scopeSet.ScopeSetId;
                            scopeSet = await _googleScope.ReadDefaultScopeSetAsync( ctx );
                            scopeSet.ScopeSetId = scopeSetId;
                        }

                        // Clone the current AuthScopeSet to be able to go throught the AuthScopeSet of the user and modify it's values.
                        AuthScopeSet scopeSetCopy = scopeSet.Clone();

                        // For each scopes check if the scope is waiting then put them in rejected and update the AuthScopeSet.
                        foreach( AuthScopeItem scope in scopeSetCopy.Scopes)
                        {
                            if( scopeSet.CheckStatus( ScopeWARStatus.Waiting, scope.ScopeName ) )
                            {
                                AuthScopeItem authScopeItem = new AuthScopeItem( scope.ScopeName, ScopeWARStatus.Rejected );
                                scopeSet.Add( authScopeItem );
                            }
                        }

                        // Update database with the updated AuthScopeSet.
                        await _googleScope.AuthScopeSetTable.AddOrUpdateScopesAsync( ctx, current.ActualUser.UserId, scopeSet );

                    }
                }
                catch( HttpRequestException e )
                {
                    Console.WriteLine( "\nException Caught!" );
                    Console.WriteLine( "Message :{0} ", e.Message );
                }
            }
        }

        public class FacebookScope
        {
            public string permission { get; set; }
            public string status { get; set; }
        }

        public class FacebookScopeList
        {
            public List<FacebookScope> data { get; set; }
        }

        public class GoogleJsonResponse
        {
            public string issued_to { get; set; }
            public string audience { get; set; }
            public string user_id { get; set; }
            public string scope { get; set; }
            public int expires_in { get; set; }
            public string email { get; set; }
            public bool verified_email { get; set; }
            public string access_type { get; set; }
        }
    }
}
