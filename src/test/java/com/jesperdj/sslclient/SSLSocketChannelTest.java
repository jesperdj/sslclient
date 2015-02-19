/*
 * Copyright 2015 Jesper de Jong
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
package com.jesperdj.sslclient;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class SSLSocketChannelTest {
    private static final Logger LOG = LoggerFactory.getLogger(SSLSocketChannelTest.class);

    @Test
    public void testHttpsExchange() throws IOException, NoSuchAlgorithmException {
        // If you try www.google.com you will see that it does not properly do the SSL close handshake;
        // it closes the connection without responding to our close notify alert
        final SocketAddress address = new InetSocketAddress("www.oracle.com", 443);

        LOG.debug("Opening channel");
        try (final SSLSocketChannel<String> channel = SSLSocketChannel.open(address, SSLSocketChannelTest::encode,
                SSLSocketChannelTest::decode, 256, 8192)) {
            LOG.debug("Channel opened, initial handshake done");

            LOG.debug("Sending request");
            channel.send("GET /index.html HTTP/1.0\r\n\r\n");

            LOG.debug("Receiving response");
            final String response = channel.receive();
            LOG.debug("Response received: {}", response);
        } finally {
            LOG.debug("Channel closed");
        }
    }

    private static void encode(String request, ByteBuffer buffer) {
        LOG.debug("Encoding request: {}", request);
        buffer.put(request.getBytes(StandardCharsets.US_ASCII));
    }

    private static String decode(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            LOG.debug("Decoding response");

            // NOTE: This is a bit crappy, it doesn't receive the complete HTTP response, it just takes what is in the
            // buffer when this is called.

            final byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        } else {
            LOG.debug("Decode: not enough data");
            return null;
        }
    }
}
