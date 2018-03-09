/*
 * Copyright 2017 Bepal
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
 * following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or
 * promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package pro.bepal;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.*;
import org.bitcoinj.params.MainNetParams;
import org.testng.annotations.Test;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.List;

/**
 * bip-0039 implement
 * <span>https://github.com/Bepal/bips/blob/master/bip-0039.mediawiki</span>
 * bip-0044 implement
 * <span>https://github.com/Bepal/bips/blob/master/bip-0044.mediawiki</span>
 *
 * @author bepal
 */
public class Program {
    /**
     * Chinese text typically does not use any spaces as word separators.
     * For the sake of uniformity, we propose to use normal ASCII spaces (0x20) to separate words as per standard.
     *
     * <span>https://github.com/Bepal/bips/blob/master/bip-0039/chinese_simplified.txt</span>
     */
    private static final String BIP39_CHINESE_RESOURCE_NAME = "mnemonic/wordlist/zh_cn.txt";

    private static final String BIP39_CHINESE_SHA256 = "bfd683b91db88609fabad8968c7efe4bf69606bf5a49ac4a4ba5e355955670cb";

    /**
     * DefaultWords English text
     *
     * <span>https://github.com/Bepal/bips/blob/master/bip-0039/english.txt</span>
     */
    private static final String BIP39_ENGLISH_RESOURCE_NAME = "mnemonic/wordlist/english.txt";


    /**
     * create master private key with mnemonicCode
     *
     * @return
     */
    private DeterministicKey createMasterPrivateKey() {

        //private key seed
        byte[] seed = null;

        try {
            //load mnemonic code，use chinese
            InputStream stream = MnemonicCode.class.getResourceAsStream(BIP39_CHINESE_RESOURCE_NAME);
            if (stream == null) {
                throw new FileNotFoundException(BIP39_CHINESE_RESOURCE_NAME);
            }

            MnemonicCode mnemonicCode = new MnemonicCode(stream, BIP39_CHINESE_SHA256);

            SecureRandom secureRandom = new SecureRandom();
            byte[] randomData = secureRandom.random();
            //random generate mnemonic code
            List<String> seedCode = mnemonicCode.toMnemonic(randomData);
            //print mnemonic code
            int size = seedCode.size();
            for (int i = 0; i < size; i++) {
                System.out.println("index:" + i + ",code:" + seedCode.get(i));
            }
            seed = MnemonicCode.toSeed(seedCode, "");
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("create seed fail");
        }

        if (seed == null || seed.length == 0) {
            System.err.println("seed is null");
        }

        //create master private key
        DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
        return masterPrivateKey;
    }

    @Test
    public void testCreateMasterPrivateKey() {
        DeterministicKey masterPrivateKey = createMasterPrivateKey();
        System.out.println(masterPrivateKey.getPrivKey());
    }

    /**
     * create bitcoin address from root private key
     * implement bip-0044
     *
     * @param rootKey root private key
     * @param count   address count
     */
    private void createBitcoinAddress(DeterministicKey rootKey, Integer count) {

        DeterministicHierarchy rootHierarchy = new DeterministicHierarchy(rootKey);
        //implement bip-0044 bitcoin path m / 44' / 0' / 0'
        ImmutableList<ChildNumber> thisRootPath = ImmutableList.of(new ChildNumber(44, true),
                new ChildNumber(0, true), ChildNumber.ZERO_HARDENED);
        DeterministicHierarchy hierarchy = new DeterministicHierarchy(rootHierarchy.get(thisRootPath, false, true));

        //bitcoin network parameters
        NetworkParameters parameters = MainNetParams.get();

        //create external address and internal address
        for (int i = 0; i < count; i++) {
            ECKey ecKey = hierarchy.get(ImmutableList.of(ChildNumber.ZERO, new ChildNumber(i)), true, true);
            System.out.printf("external address %d: %s\n", i + 1, LegacyAddress.fromPubKeyHash(parameters, ecKey.getPubKeyHash()).toBase58());
        }
        for (int i = 0; i < count; i++) {
            ECKey ecKey = hierarchy.get(ImmutableList.of(ChildNumber.ONE, new ChildNumber(i)), true, true);
            System.out.printf("internal address %d: %s\n", i + 1, LegacyAddress.fromPubKeyHash(parameters, ecKey.getPubKeyHash()).toBase58());
        }
    }

    @Test
    public void testCreateBitcoinAddress() {

//        uncomment this four line code , use you own mnemonic code
//        String[] words = new String[]{"a","a","a","a","a","a","a","a","a","a","a","a"};
//        List<String> seedCode = Arrays.asList(words);
//        byte[] seed = MnemonicCode.toSeed(seedCode, "");
//        DeterministicKey rootKey = HDKeyDerivation.createMasterPrivateKey(seed);

        DeterministicKey rootKey = createMasterPrivateKey();
        createBitcoinAddress(rootKey, 10);

    }

    /**
     * create eos privatekey, wif format
     *
     * @param rootKey root private key
     */
    private void createEosPrivateKey(DeterministicKey rootKey) {

        DeterministicHierarchy rootHierarchy = new DeterministicHierarchy(rootKey);
        //implement bip-0044 eos path m / 44' / 194' / 0'
        ImmutableList<ChildNumber> thisRootPath = ImmutableList.of(new ChildNumber(44, true),
                new ChildNumber(194, true), ChildNumber.ZERO_HARDENED);
        DeterministicHierarchy hierarchy = new DeterministicHierarchy(rootHierarchy.get(thisRootPath, false, true));

        //take 0
        ECKey ecKey = hierarchy.get(ImmutableList.of(ChildNumber.ZERO, new ChildNumber(0)), true, true);

        String privateKeyHex = ecKey.getPrivateKeyAsHex();

        //convert to wif format
        WalletImportFormatKit kit = new WalletImportFormatKit();
        String wifString = kit.privateKeyToWIF(privateKeyHex, WalletImportFormatKit.MAINNET);

        System.out.printf("EOS WIF Private Key = %s", wifString);

    }


    @Test
    public void testCreateEos() {

        //uncomment this four line code , use you own mnemonic code
//        String[] words = new String[]{"a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a"};
//        List<String> seedCode = Arrays.asList(words);
//        byte[] seed = MnemonicCode.toSeed(seedCode, "");
//        DeterministicKey rootKey = HDKeyDerivation.createMasterPrivateKey(seed);

        DeterministicKey rootKey = createMasterPrivateKey();

        createEosPrivateKey(rootKey);


    }


}
