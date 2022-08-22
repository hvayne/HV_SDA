using CefSharp;
using System.IO;

namespace Steam_Desktop_Authenticator
{
    class ResourceResponseFilter : IResponseFilter
    {
        public void Dispose()
        {

        }

        public FilterStatus Filter(Stream dataIn, out long dataInRead, Stream dataOut, out long dataOutWritten)
        {
            dataInRead = 0;
            dataOutWritten = 0;
            return FilterStatus.Error;
        }

        public bool InitFilter()
        {
            return false;
        }
    }
}
