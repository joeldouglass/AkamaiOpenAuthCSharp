/*
 * This is a C# port of the Java implementation found here: https://github.com/akamai-open/edgegrid-auth-java
 *
 * Copyright 2013 Akamai Technologies, Inc. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Class representing the EdgeGrid version 1 signer that implements the {@link RequestSigner}.
 * 
 * <p>
 * The signer sets the Authorization header in the request as algorithm name, ' ' (space), followed by
 * an ordered list of name=value fields separated with ';'.
 * </p>
 * 
 * <p>
 * The names of the fields are:
 * </p>
 * 
 * <ol>
 * <li>
 * client_token: for the client token;
 * </li>
 * <li>
 * access_token: for the access token;
 * </li>
 * <li>
 * timestamp: for the timestamp when the request is signed;
 * </li>
 * <li>
 * </li>
 * nonce: for possible nonce checking;
 * <li>
 * signature: for the request signature.
 * </li>
 * </ol>
 *
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AkamaiOpenAuth.Authentication
{
	public class EdgeGridV1Signer : IRequestSigner
	{

		/**
	 * The logger used for logging.
	 */
		//private static final Logger LOGGER = LoggerFactory.getLogger(EdgeGridV1Signer.class);

		/**
	 * The signing algorithm for the EdgeGrid version 1 protocol.
	 */
		private const string Algorithm = "EG1-HMAC-SHA256";

		/**
	 * The HMAC algorithm used.
	 */
		private const string HmacAlg = "HmacSHA256";

		/**
	 * The message digest algorithm used.
	 */
		private const string MdAlg = "SHA-256";

		/**
	 * The charset used for String to bytes conversions.
	 */
		private const string Charset = "UTF-8";

		/**
	 * The field name for the client token in the authorization header.
	 */
		private const string AuthClientTokenName = "client_token";

		/**
	 * The field name for the access token in the authorization header.
	 */
		private const string AuthAccessTokenName = "access_token";

		/**
	 * The field name for the time stamp in the authorization header.
	 */
		private const string AuthTimestampName = "timestamp";

		/**
	 * The field name for the nonce in the authorization header.
	 */
		private const string AuthNonceName = "nonce";

		/**
	 * The field name for the signature in the authorization header.
	 */
		private const string AuthSignatureName = "signature";

		/**
	 * The ordered list of header names to include in the signature.
	 */
		private readonly List<string> _headersToInclude;

		/**
	 * The maximum allowed body size in bytes for POST and PUT requests.
	 */
		private readonly int _maxBodySize;

		/**
	 * Constructor
	 * 
	 * <p>
	 * Note: the parameters should be published by the service provider when the service
	 * is published. Refer to the API documentation for any special instructions.
	 * </p>
	 * 
	 * @param headers the ordered list of header names to include in the signature.
	 * @param maxBodySize the maximum allowed body size in bytes for POST and PUT requests.
	 */

		public EdgeGridV1Signer(List<string> headers, int maxBodySize)
		{
			_headersToInclude = headers;
			_maxBodySize = maxBodySize;
		}

		/**
	 * Signs the given request with the given client credential.
	 * 
	 * @param request the request to sign.
	 * @param credential the credential used in the signing.
	 * @return the signed request.
	 * @throws RequestSigningException
	 */

		public HttpRequestMessage Sign(HttpRequestMessage request, IClientCredential credential)
		{

			string timeStamp = GetTimeStamp(DateTime.UtcNow);

			StringBuilder sb = new StringBuilder();
			sb.Append(Algorithm);
			sb.Append(' ');
			sb.Append(AuthClientTokenName);
			sb.Append('=');
			sb.Append(credential.ClientToken);
			sb.Append(';');

			sb.Append(AuthAccessTokenName);
			sb.Append('=');
			sb.Append(credential.AccessToken);
			sb.Append(';');

			sb.Append(AuthTimestampName);
			sb.Append('=');
			sb.Append(timeStamp);
			sb.Append(';');

			string nonce = Guid.NewGuid().ToString();
			sb.Append(AuthNonceName);
			sb.Append('=');
			sb.Append(nonce);
			sb.Append(';');

			string authData = sb.ToString();

			try
			{
				string clientSecret = credential.ClientSecret;

				byte[] signingKeyBytes = Sign(timeStamp, Encoding.GetEncoding(Charset).GetBytes(clientSecret), HmacAlg);
				string signingKey = Convert.ToBase64String(signingKeyBytes);

				CanonicalizerHelper requestResult = GetCanonicalizedRequest(request);
				HttpRequestMessage updatedRequest = requestResult.Request;

				string requestData = requestResult.CanonicalizedData;

				StringBuilder signData = new StringBuilder(requestData);
				signData.Append(authData);

				string stringToSign = signData.ToString();

				//if (LOGGER.isDebugEnabled()) {
				//	LOGGER.debug(String.format("String to sign : '%s'", stringToSign));
				//}

				byte[] signatureBytes = Sign(stringToSign, Encoding.GetEncoding(Charset).GetBytes(signingKey), HmacAlg);
				string signature = Convert.ToBase64String(signatureBytes);

				//if (LOGGER.isDebugEnabled()) {
				//	LOGGER.debug(String.format("Signature : '%s'", signature));
				//}

				// add the signature
				sb.Append(AuthSignatureName);
				sb.Append('=');
				sb.Append(signature);

				String authHeader = sb.ToString();

				updatedRequest.Headers.Add("Authorization", authHeader);

				return updatedRequest;
			}
			catch (Exception e)
			{
				throw new RequestSigningException("Failed to sign: invalid string encoding", e);
			}
		}

		/**
	 * Gets the canonicalized data of the given request.
	 * 
	 * <p>
	 * The canonicalized data contains the list of fields separate with a tab '\t':
	 * </p>
	 * 
	 * <ol>
	 * <li>
	 * the request method (GET/PUT etc.) in upper case;
	 * </li>
	 * <li>
	 * the scheme (http/https) in lower case;
	 * </li>
	 * <li>
	 * the host from the Host header in lower case;
	 * </li>
	 * <li>
	 * the relative URL that contains the path and query portions of the URL,
	 * as it appears in the HTTP request line, see {@link #canonicalizeUri};
	 * </li>
	 * <li>
	 * the canonicalized request headers, see {@link #canonicalizeHeaders};
	 * </li>
	 * <li>
	 * the content hash of the request body for POST requests, see {@link #getContentHash}.
	 * </li>
	 * </ol>
	 * 
	 * @param request the request.
	 * @return the canonicalized data, and the possibly updated request.
	 * @throws RequestSigningException
	 */

		private CanonicalizerHelper GetCanonicalizedRequest(HttpRequestMessage request)
		{
			StringBuilder sb = new StringBuilder();

			string method = request.Method.Method;
			if (string.IsNullOrEmpty(method))
			{
				throw new RequestSigningException("Invalid request: empty request method");
			}
			sb.Append(method.ToUpper());
			sb.Append('\t');

			Uri uri = request.RequestUri;

			string scheme = uri.Scheme;
			if (string.IsNullOrEmpty(scheme))
			{
				throw new RequestSigningException("Invalid request: empty request scheme");
			}
			sb.Append(scheme.ToLower());
			sb.Append('\t');

			string host = GetHost(request);
			if (string.IsNullOrEmpty(host))
			{
				throw new RequestSigningException("Invalid request: empty host");
			}
			sb.Append(host.ToLower());
			sb.Append('\t');

			string rawRelativeUrl = request.RequestUri.PathAndQuery;
			string relativeUrl = CanonicalizeUri(rawRelativeUrl);
			sb.Append(relativeUrl);
			sb.Append('\t');

			string canonicalizedHeaders = CanonicalizeHeaders(request);
			sb.Append(canonicalizedHeaders);
			sb.Append('\t');

			CanonicalizerHelper contentHashResult = GetContentHash(request);
			string contentHash = contentHashResult.CanonicalizedData;
			sb.Append(contentHash);
			sb.Append('\t');

			string data = sb.ToString();

			return new CanonicalizerHelper(data, contentHashResult.Request);
		}

		/**
	 * Get the canonicalized uri.
	 * 
	 * <p>
	 * The canonicalization is done as the following:
	 * </p>
	 * 
	 * <ul>
	 * <li>
	 * If the path is null or empty, set it to "/".
	 * </li>
	 * <li>
	 * If the path does not start with "/", add "/" to the beginning.
	 * </li>
	 * </ul>
	 * 
	 * @param uri the original uri.
	 * @return the canonicalized uri.
	 */

		protected string CanonicalizeUri(String uri)
		{
			if (string.IsNullOrEmpty(uri))
			{
				return "/";
			}

			if (uri[0] != '/')
			{
				uri = "/" + uri;
			}

			return uri;
		}

		/**
	 * Get the canonicalized data for the request headers.
	 * 
	 * <p>
	 * The canonicalization is done as the following:
	 * </p>
	 * 
	 * <p>
	 * For each entry in the {@link #headersToInclude},
	 * </p>
	 * 
	 * <ul>
	 * <li>
	 * get the first header value for the name;
	 * </li>
	 * <li>
	 * trim the leading and trailing white spaces;
	 * </li>
	 * <li>
	 * replace all repeated white spaces with a single space;
	 * <p>
	 * Note: the canonicalized data is used for signature only, as this step might alter the header value.
	 * </p>
	 * </li>
	 * <li>
	 * concatenate the name:value pairs with a tab '\t' separator. The name field is all in lower cases.
	 * </li>
	 * <li>
	 * terminate the headers with another tab ('\t') separator.
	 * </li>
	 * </ul>
	 * 
	 * @param request the request.
	 * @return the canonicalized data for the request headers.
	 */

		private String CanonicalizeHeaders(HttpRequestMessage request)
		{
			StringBuilder sb = new StringBuilder();
			foreach (string headerName in _headersToInclude)
			{
				// only use the first entry if more than one headers with the same name
				string headerValue = request.Headers.GetValues(headerName).FirstOrDefault();
				if (headerValue != null)
				{
					// trim the header value
					headerValue = headerValue.Trim();

					if (!string.IsNullOrEmpty(headerValue))
					{
						Regex p = new Regex("\\s+");
						headerValue = p.Replace(headerValue, " ");

						sb.Append(headerName.ToLower());
						sb.Append(':');
						sb.Append(headerValue);
						sb.Append('\t');
					}
				}
			}

			return sb.ToString();
		}

		/**
	 * Get the SHA-256 hash of the POST body.
	 * 
	 * @param request the request.
	 * @return the canonicalized data, and the possibly updated request.
	 * @throws RequestSigningException
	 */

		private CanonicalizerHelper GetContentHash(HttpRequestMessage request)
		{
			String data = "";
			HttpRequestMessage updatedRequest = request;

			// only do hash for POSTs for this version
			if ("POST".Equals(request.Method.Method, StringComparison.InvariantCultureIgnoreCase))
			{

				HttpContent content = request.Content;
				try
				{
					if (content != null)
					{

						MemoryStream memoryStream = new MemoryStream();
						Task task = content.CopyToAsync(memoryStream);

						task.Wait();

						if (memoryStream.Length > _maxBodySize)
						{
							throw new RequestSigningException("Content body too large.");
						}

						byte[] contentBytes = memoryStream.ToArray();

						//if (LOGGER.isDebugEnabled())
						//{
						//	LOGGER.debug(String.format("Content: %s", Base64.encodeBase64String(contentBytes)));
						//}

						byte[] digestBytes = GetHash(contentBytes);

						//if (LOGGER.isDebugEnabled())
						//{
						//	LOGGER.debug(String.format("Content hash: %s", Base64.encodeBase64String(digestBytes)));
						//}

						// TODO - Do we need this??
						// for non-retryable content, reset the content for downstream handlers
						//if (!content.retrySupported())
						//{
						//	HttpContent newContent = new ByteArrayContent(content.getType(), contentBytes);
						//	updatedRequest = request.setContent(newContent);
						//}

						data = Convert.ToBase64String(digestBytes);
					}
				}
				catch (IOException ioe)
				{
					throw new RequestSigningException("Failed to get content hash: failed to read content", ioe);
				}					

			}

			return new CanonicalizerHelper(data, updatedRequest);
		}

		/**
	 * Helper method to calculate the message digest.
	 * 
	 * @param contentBytes the content bytes for digesting.
	 * @return the digest.
	 * @throws RequestSigningException
	 */

		private static byte[] GetHash(byte[] contentBytes)
		{
			var hashAlgorithm = HashAlgorithm.Create(MdAlg);
			if (hashAlgorithm != null)
			{
				byte[] digestBytes = hashAlgorithm.ComputeHash(contentBytes);
				return digestBytes;
			}
			else
			{
				throw new RequestSigningException("Failed to get request hash: algorithm not found");
			}
		}

		/**
	 * Helper method to calculate the HMAC signature of a given string.
	 * 
	 * @param s the string to sign.
	 * @param key the key for the signature.
	 * @param algorithm the signing algorithm.
	 * @return the HMac signature.
	 * @throws RequestSigningException
	 */

		private static byte[] Sign(string s, byte[] key, string algorithm)
		{
			byte[] valueBytes = Encoding.GetEncoding(Charset).GetBytes(s);

			using (HMAC hmac = HMAC.Create(algorithm))
			{
				hmac.Key = key;

				// Compute the hash of the input file. 
				return hmac.ComputeHash(valueBytes);
			}
		}

		/**
	 * Helper method to get the host name from the request header.
	 * 
	 * @param request the request.
	 * @return host name.
	 */

		private static string GetHost(HttpRequestMessage request)
		{
			string hostName = request.Headers.GetValues("host").FirstOrDefault();

			return hostName;
		}

		/**
	 * Helper to get the formatted time stamp. 
	 * 
	 * @param time the time stamp as millisecond since the UNIX epoch.
	 * @return the formatted time stamp.
	 */

		private static string GetTimeStamp(DateTime dateTime)
		{
			return dateTime.ToString("yyyyMMdd'T'HH:mm:ssZ");
		}

		/**
	 * Helper class representing the canonicalized data and possibly updated request.
	 *
	 */

		private class CanonicalizerHelper
		{

			/**
		 * The canonicalized data.
		 */
			private readonly string _canonicalizedData;

			/**
		 * The request.
		 */
			private readonly HttpRequestMessage _request;

			/**
		 * Constructor.
		 * 
		 * @param data the canonicalized data.
		 * @param request the request.
		 */

			public CanonicalizerHelper(string data, HttpRequestMessage request)
			{
				_canonicalizedData = data;
				_request = request;
			}

			/**
		 * Get the canonicalized data.
		 * @return the canonicalized data.
		 */

			public string CanonicalizedData
			{
				get { return _canonicalizedData; }
			}

			/**
		 * Get the request.
		 * @return the request.
		 */

			public HttpRequestMessage Request
			{
				get { return _request; }
			}
		}
	}
}