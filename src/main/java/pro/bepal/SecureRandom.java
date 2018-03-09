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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * SecureRandom
 *
 * @author bepal
 */
public class SecureRandom {

    /**
     * random
     *
     * @return
     * @throws Exception
     */
    public byte[] random() throws Exception {
        Long startTime = System.currentTimeMillis();
        int count = 1000000;
        java.security.SecureRandom secureRandom = new java.security.SecureRandom();
        byte[] bytes = new byte[32];
        Integer[] sCount = new Integer[256];
        //生成100w个256的随机数
        for (int i = 0; i < count; i++) {
            secureRandom.nextBytes(bytes);
            boolean[] concatBits = bytesToBits(bytes);
            String string = arrayToString(concatBits);
            String[] strings = string.split("");
            for (int j = 0; j < strings.length; j++) {
                if ("1".equals(strings[j])) {
                    if (sCount[j] == null) {
                        sCount[j] = 0;
                    }
                    sCount[j] += 1;
                }
            }
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (Integer c : sCount) {
            outputStream.write(c);
        }
        return Arrays.copyOfRange(outputStream.toByteArray(), 0, 16);
    }

    /**
     * arrayToString
     *
     * @param concatBits
     * @return
     */
    private String arrayToString(boolean[] concatBits) {
        StringBuilder builder = new StringBuilder();
        for (boolean ok : concatBits) {
            builder.append(ok ? "1" : 0);
        }
        return builder.toString();
    }


    /**
     * bytesToBits
     *
     * @param data
     * @return
     */
    private boolean[] bytesToBits(byte[] data) {
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; ++i)
            for (int j = 0; j < 8; ++j) {
                bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
            }
        return bits;
    }

}
