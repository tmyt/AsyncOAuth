using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Web.Http;
using Windows.Web.Http.Filters;
using Windows.Web.Http.Headers;

namespace AsyncOAuth
{
    // idea is based on http://blogs.msdn.com/b/henrikn/archive/2012/02/16/extending-httpclient-with-oauth-to-access-twitter.aspx
    public class OAuthMessageFilter : IHttpFilter
    {
        private IHttpFilter innerFilter;
        string consumerKey;
        string consumerSecret;
        Token token;
        IEnumerable<KeyValuePair<string, string>> parameters;

        public OAuthMessageFilter(string consumerKey, string consumerSecret, Token token = null, IEnumerable<KeyValuePair<string, string>> optionalOAuthHeaderParameters = null)
            : this(new HttpBaseProtocolFilter(), consumerKey, consumerSecret, token, optionalOAuthHeaderParameters)
        {
        }

        public OAuthMessageFilter(IHttpFilter innerFilter, string consumerKey, string consumerSecret, Token token = null, IEnumerable<KeyValuePair<string, string>> optionalOAuthHeaderParameters = null)
        {
            this.innerFilter = innerFilter;
            this.consumerKey = consumerKey;
            this.consumerSecret = consumerSecret;
            this.token = token;
            this.parameters = optionalOAuthHeaderParameters ?? Enumerable.Empty<KeyValuePair<string, string>>();
        }


        public IAsyncOperationWithProgress<HttpResponseMessage, HttpProgress> SendRequestAsync(HttpRequestMessage request)
        {
            var sendParameter = parameters;
            var task = Task.FromResult(request);
            if (request.Method.Method == "POST")
            {
                task = Task.Run(async () =>
                {
                    // form url encoded content
                    if (request.Content is HttpFormUrlEncodedContent)
                    {
                        // url encoded string
                        var extraParameter = await request.Content.ReadAsStringAsync().AsTask().ConfigureAwait(false);
                        var parsed = Utility.ParseQueryString(extraParameter, true); // url decoded
                        sendParameter = sendParameter.Concat(parsed);

                        request.Content = new HttpFormUrlEncodedContent(parsed);
                    }
                    return request;
                });
            }

            return task.ContinueWith(t =>
            {
                var req = t.Result;
                var headerParams = OAuthUtility.BuildBasicParameters(
                    consumerKey, consumerSecret,
                    req.RequestUri.OriginalString, req.Method, token,
                    sendParameter);
                headerParams = headerParams.Concat(parameters);

                var header = headerParams.Select(p => p.Key + "=" + p.Value.Wrap("\"")).ToString(",");
                req.Headers.Authorization = new HttpCredentialsHeaderValue("OAuth", header);
                
                return innerFilter.SendRequestAsync(req);
            }).Result;
        }

        public void Dispose()
        {
            innerFilter.Dispose();
        }
    }
}