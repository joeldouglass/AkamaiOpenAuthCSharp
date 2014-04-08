/*
 * This is a C# port of the Java implementation found here: https://github.com/akamai-open/edgegrid-auth-java
 *
 * * Copyright 2013 Akamai Technologies, Inc. All Rights Reserved.
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
 * Default implementation of the {@link ClientCredential}.
 *
 */


using System;

namespace AkamaiOpenAuth.Authentication
{
	public class DefaultCredential : IClientCredential
	{

		/**
	 * The client token.
	 */
		private readonly string _clientToken;

		/**
	 * The access token.
	 */
		private readonly string _accessToken;

		/**
	 * The secret associated with the client token.
	 */
		private readonly string _clientSecret;

		/**
	 * Constructor.
	 * 
	 * @param clientToken the client token, cannot be null or empty.
	 * @param accessToken the access token, cannot be null or empty.
	 * @param clientSecret the client secret, cannot be null or empty.
	 * 
	 * @throws IllegalArgumentException if any of the parameters is null or empty.
	 */
		public DefaultCredential(string clientToken, string accessToken, string clientSecret)
		{
			if (string.IsNullOrEmpty(clientToken))
			{
				throw new ArgumentException("clientToken cannot be empty.");
			}
			if (string.IsNullOrEmpty(accessToken))
			{
				throw new ArgumentException("accessToken cannot be empty.");
			}
			if (string.IsNullOrEmpty(clientSecret))
			{
				throw new ArgumentException("clientSecret cannot be empty.");
			}

			_clientToken = clientToken;
			_accessToken = accessToken;
			_clientSecret = clientSecret;
		}

		/**
	 * Gets the client token.
	 * @return The client token.
	 */
		public string ClientToken
		{
			get
			{
				return _clientToken;
			}
		}

		/**
	 * Gets the access token.
	 * @return the access token.
	 */
		public string AccessToken
		{
			get
			{
				return _accessToken;
			}
		}

		/**
	 * Gets the secret associated with the client token.
	 * @return the secret.
	 */
		public string ClientSecret
		{
			get
			{
				return _clientSecret;
			}
		}
	}
}