﻿/*
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
 * Interface representing the client credential that is used in service requests.
 * 
 * It contains the client token that represents the service client, the client secret
 * that is associated with the client token used for request signing, and the access token
 * that represents the authorizations the client has for accessing the service.
 *
 */
namespace AkamaiOpenAuth.Authentication
{
	public interface IClientCredential {
		/**
	 * Gets the client token.
	 * @return The client token.
	 */
		string ClientToken { get; }
	
		/**
	 * Gets the access token.
	 * @return the access token.
	 */
		string AccessToken { get; }
	
		/**
	 * Gets the secret associated with the client token.
	 * @return the secret.
	 */
		string ClientSecret { get; }
	}
}