/*
 * Copyright © 2022, 2023 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.run;

import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.core.Version;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.FileLogger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.Logger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.log.SysOutLogger;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ApplicationProtocolConnectionFactory;
import de.tomcory.heimdall.scanner.traffic.connection.encryptionLayer.kwik.server.ServerConnector;
import org.apache.commons.cli.*;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple sample HTTP3 Web server.
 */
public class SampleWebServer {

    private static void usageAndExit() {
        System.err.println("Usage: [--noRetry] cert file, cert key file, port number, www dir");
        System.exit(1);
    }

    public static void main(String[] rawArgs) throws Exception {
        Options cmdLineOptions = new Options();
        cmdLineOptions.addOption(null, "noRetry", false, "disable always use retry");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(cmdLineOptions, rawArgs);
        }
        catch (ParseException argError) {
            System.out.println("Invalid argument: " + argError.getMessage());
            usageAndExit();
        }

        List<String> args = cmd.getArgList();
        if (args.size() < 4) {
            usageAndExit();
        }

        Logger log;
        File logDir = new File("/logs");
        if (logDir.exists() && logDir.isDirectory() && logDir.canWrite()) {
            log = new FileLogger(new File(logDir, "kwikserver.log"));
        }
        else {
            log = new SysOutLogger();
        }
        log.timeFormat(Logger.TimeFormat.Long);
        log.logWarning(true);
        log.logInfo(true);


        File certificateFile = new File(args.get(0));
        if (!certificateFile.exists()) {
            System.err.println("Cannot open certificate file " + args.get(0));
            System.exit(1);
        }

        File certificateKeyFile = new File(args.get(1));
        if (!certificateKeyFile.exists()) {
            System.err.println("Cannot open certificate file " + args.get(1));
            System.exit(1);
        }

        int port = Integer.parseInt(args.get(2));

        File wwwDir = new File(args.get(3));
        if (!wwwDir.exists() || !wwwDir.isDirectory() || !wwwDir.canRead()) {
            System.err.println("Cannot read www dir '" + wwwDir + "'");
            System.exit(1);
        }

        List<Version> supportedVersions = new ArrayList<>();
        supportedVersions.add(Version.QUIC_version_1);
        supportedVersions.add(Version.QUIC_version_2);

        boolean requireRetry = ! cmd.hasOption("noRetry");
        ServerConnector serverConnector = new ServerConnector(port, new FileInputStream(certificateFile), new FileInputStream(certificateKeyFile), supportedVersions, requireRetry, log);
        registerHttp3(serverConnector, wwwDir, supportedVersions, log);

        serverConnector.start();
        log.info("Kwik server " + KwikVersion.getVersion() + " started; supported application protocols: "
                + serverConnector.getRegisteredApplicationProtocols());
    }

    private static void registerHttp3(ServerConnector serverConnector, File wwwDir, List<Version> supportedVersions, Logger log) {
        ApplicationProtocolConnectionFactory http3ApplicationProtocolConnectionFactory = null;

        try {
            // If flupke server plugin is on classpath, load the http3 connection factory class.
            Class<?> http3FactoryClass = SampleWebServer.class.getClassLoader().loadClass("net.luminis.http3.server.Http3ApplicationProtocolFactory");
            http3ApplicationProtocolConnectionFactory = (ApplicationProtocolConnectionFactory)
                    http3FactoryClass.getDeclaredConstructor(new Class[]{ File.class }).newInstance(wwwDir);
            log.info("Loading Flupke H3 server plugin");

            serverConnector.registerApplicationProtocol("h3", http3ApplicationProtocolConnectionFactory);
        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            log.error("No H3 protocol: Flupke plugin not found.");
            System.exit(1);
        }
    }
}
