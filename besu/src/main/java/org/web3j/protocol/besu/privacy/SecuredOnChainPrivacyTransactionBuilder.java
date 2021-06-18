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
package org.web3j.protocol.besu.privacy;

import java.math.BigInteger;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.crypto.signer.Signer;
import org.web3j.protocol.eea.crypto.PrivateTransactionEncoder;
import org.web3j.protocol.eea.crypto.RawPrivateTransaction;
import org.web3j.tx.gas.BesuPrivacyGasProvider;
import org.web3j.utils.Base64String;
import org.web3j.utils.Numeric;
import org.web3j.utils.Restriction;

public class SecuredOnChainPrivacyTransactionBuilder extends OnChainPrivacyTransactionBuilder {

    private final Signer signer;

    public SecuredOnChainPrivacyTransactionBuilder(
            final long chainId,
            final BesuPrivacyGasProvider gasProvider,
            final Restriction restriction,
            final Signer signer) {
        super(chainId, gasProvider, restriction);
        this.signer = signer;
    }

    @Override
    public String buildOnChainPrivateTransaction(
            final Base64String privacyGroupId,
            final Credentials credentials,
            final Base64String enclaveKey,
            final BigInteger nonce,
            final String call) {
        RawPrivateTransaction rawTransaction =
                RawPrivateTransaction.createTransaction(
                        nonce,
                        gasProvider.getGasPrice(),
                        gasProvider.getGasLimit(),
                        OnChainPrivacyPrecompiledContract,
                        call,
                        enclaveKey,
                        privacyGroupId,
                        restriction);

        final byte[] encodedTransaction = PrivateTransactionEncoder.encode(rawTransaction, chainId);

        final Sign.SignatureData signatureData = signer.sign(encodedTransaction);

        final Sign.SignatureData eip155SignatureData =
                TransactionEncoder.createEip155SignatureData(signatureData, chainId);

        return Numeric.toHexString(
                PrivateTransactionEncoder.encode(rawTransaction, eip155SignatureData));
    }
}
