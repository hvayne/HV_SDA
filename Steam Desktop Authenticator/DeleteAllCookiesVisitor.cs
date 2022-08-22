using CefSharp;

namespace Steam_Desktop_Authenticator
{
    public class DeleteAllCookiesVisitor : ICookieVisitor
    {
        public void Dispose()
        {

        }

        public bool Visit(Cookie cookie, int count, int total, ref bool deleteCookie)
        {
            deleteCookie = true;
            return true;
        }
    }
}
