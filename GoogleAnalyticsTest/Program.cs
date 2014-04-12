/*
Copyright 2011 Google Inc

Licensed under the Apache License, Version 2.0(the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Diagnostics;
using DotNetOpenAuth.OAuth2;
using Google.Apis.Authentication;
using Google.Apis.Authentication.OAuth2;
using Google.Apis.Authentication.OAuth2.DotNetOpenAuth;
using Google.Apis.Util;
using Google.Apis.Analytics.v3;
using Google.Apis.Analytics.v3.Data;
using System.Text;



namespace GoogleAnalyticsTest
{
    /// <summary>
    /// This sample demonstrates the simplest use case for an OAuth2 service. 
    /// The schema provided here can be applied to every request requiring authentication.
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {


            
            var tokenProvider = new NativeApplicationClient(GoogleAuthenticationServer.Description);
            tokenProvider.ClientIdentifier = "1083546295784-9ojhd793rbmo3bpas4gs811tvdsrbhlh.apps.googleusercontent.com";
            tokenProvider.ClientSecret = "UM5t_CWw9aogor0rKCkGkRcP";

            var auth = new OAuth2Authenticator<NativeApplicationClient>(tokenProvider, AuthProvider);
            
  

            var service = new AnalyticsService(auth);
            Accounts results = service.Management.Accounts.List().Fetch();
            Console.WriteLine("List:");
            foreach (Account a in results.Items)
            {
                Console.WriteLine(a.Name);
            }
            Console.ReadKey();

        }

        private static byte[] aditionalEntropy = { 1, 2, 3, 4, 5 };



        private static IAuthorizationState AuthProvider(NativeApplicationClient argTokenProvider)
        {

            try
            {
                IAuthorizationState state = new AuthorizationState(new[] { AnalyticsService.Scopes.Analytics.GetStringValue() });
                state.Callback = new Uri(NativeApplicationClient.OutOfBandCallbackUrl);


                string refreshToken = LoadRefreshToken();
                if (!String.IsNullOrEmpty(refreshToken))
                {
                    state.RefreshToken = refreshToken;

                    if (argTokenProvider.RefreshToken(state, null))
                        return state;
                }
                
                Uri authUri = argTokenProvider.RequestUserAuthorization(state);

                Process.Start(authUri.ToString());
                Console.Write(" authorization Code: ");
                string authCode = Console.ReadLine(); //4/pBCEKiIoAJCjvZSgKaEw03eO0gdk.ctpr2xLkGjoVgrKXntQAax0QqPmbcwI
                Console.WriteLine();

                // Retrieve the access token by using the authorization code:
                var result = argTokenProvider.ProcessUserAuthorization(authCode, state);

                StoreRefreshToken(result);

                return result;

            }
            catch (Exception ex)
            {
                throw;
            }

        }




        private static string LoadRefreshToken()
        {
            return Encoding.Unicode.GetString((Convert.FromBase64String(Properties.Settings.Default.RefreshToken)));
        }

        private static void StoreRefreshToken(IAuthorizationState state)
        {
            Properties.Settings.Default.RefreshToken = Convert.ToBase64String(Encoding.Unicode.GetBytes(state.RefreshToken));
            Properties.Settings.Default.Save();
        }


    }
}