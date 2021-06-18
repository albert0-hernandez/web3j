/*
 * Copyright 2021 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.crypto.signer;

import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

public class DefaultSigner implements Signer {

    private final Credentials credentials;

    public DefaultSigner(final Credentials credentials) {
        this.credentials = credentials;
    }

    @Override
    public Sign.SignatureData sign(final byte[] encodedTransaction) {
        return Sign.signMessage(encodedTransaction, credentials.getEcKeyPair());
    }

    @Override
    public String getAddress() {
        return Keys.getAddress(getPublicKey());
    }

    @Override
    public BigInteger getPublicKey() {
        return credentials.getEcKeyPair().getPublicKey();
    }
}
