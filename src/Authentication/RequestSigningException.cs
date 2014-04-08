using System;

namespace AkamaiOpenAuth.Authentication
{
	public class RequestSigningException : Exception
	{
		public RequestSigningException(string message) : base(message)
		{
		}

		public RequestSigningException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}
