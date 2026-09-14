/*
 * Copyright © 2004-2026 L2J Server
 *
 * This file is part of L2J Server.
 *
 * L2J Server is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * L2J Server is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package com.l2jserver.loginserver.status;

import static com.l2jserver.loginserver.config.Configuration.server;
import static com.l2jserver.loginserver.config.Configuration.telnet;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.l2jserver.loginserver.GameServerTable;
import com.l2jserver.loginserver.LoginController;
import com.l2jserver.loginserver.LoginServer;

/**
 * Handles the telnet session for monitoring and managing the login server status.
 */
public final class LoginStatusThread extends Thread {

	private static final Logger LOG = LoggerFactory.getLogger(LoginStatusThread.class);

	private final Socket clientSocket;

	private final PrintWriter print;

	private final BufferedReader read;

	private boolean redirectLogger;

	private void telnetOutput(int type, String text) {
		if (type == 1) {
			System.out.println("TELNET | " + text);
		} else if (type == 2) {
			System.out.print("TELNET | " + text);
		} else if (type == 3) {
			System.out.print(text);
		} else if (type == 4) {
			System.out.println(text);
		} else {
			System.out.println("TELNET | " + text);
		}
	}

	private boolean isValidIP(Socket client) {
		InetAddress clientIP = client.getInetAddress();

		// convert IP to String, and compare with list
		String clientStringIP = clientIP.getHostAddress();

		telnetOutput(1, "Connection from: " + clientStringIP);

		// read and loop through a list of IPs, compare with them to the newIP
		if (server().isDebug()) {
			telnetOutput(2, "");
		}

		if (server().isDebug()) {
			telnetOutput(3, "Comparing ip to list...");
		}

		boolean result = false;
		for (String host : telnet().getHosts()) {
			try {
				String ipToCompare = InetAddress.getByName(host).getHostAddress();
				if (clientStringIP.equals(ipToCompare)) {
					result = true;
				}

				if (server().isDebug()) {
					telnetOutput(3, clientStringIP + " = " + ipToCompare + "(" + host + ") = " + result);
				}
			} catch (Exception ex) {
				LOG.warn("There has been an error parsing host {}!", host, ex);
			}
		}

		if (server().isDebug()) {
			telnetOutput(4, "Allow IP: " + result);
		}
		return result;
	}

	public LoginStatusThread(Socket client, int uptime, String statusPW) throws Exception {
		clientSocket = client;

		print = new PrintWriter(clientSocket.getOutputStream());
		read = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

		if (isValidIP(client)) {
			telnetOutput(1, client.getInetAddress().getHostAddress() + " accepted.");
			print.println("Welcome To The L2J Telnet Session.");
			print.println("Please Insert Your Password!");
			print.print("Password: ");
			print.flush();
			String tmpLine = read.readLine();
			if (tmpLine == null) {
				print.println("Error.");
				print.println("Disconnected...");
				print.flush();
				clientSocket.close();
			} else {
				if (!tmpLine.equals(statusPW)) {
					print.println("Incorrect Password!");
					print.println("Disconnected...");
					print.flush();
					clientSocket.close();
				} else {
					print.println("Password Correct!");
					print.println("[L2J Login Server]");
					print.print("");
					print.flush();
					start();
				}
			}
		} else {
			telnetOutput(5, "Connection attempt from " + client.getInetAddress().getHostAddress() + " rejected.");
			clientSocket.close();
		}
	}

	@Override
	public void run() {
		String userCommand = "";
		try {
			while ((userCommand.compareTo("quit") != 0) && (userCommand.compareTo("exit") != 0)) {
				userCommand = read.readLine();
				if (userCommand == null) {
					clientSocket.close();
					break;
				}
				if (userCommand.equals("help")) {
					print.println("The following is a list of all available commands: ");
					print.println("help                - shows this help.");
					print.println("status              - displays basic server statistics.");
					print.println("unblock <ip>        - removes <ip> from the ban list.");
					print.println("shutdown            - shuts down server.");
					print.println("restart             - restarts the server.");
					print.println("RedirectLogger      - Telnet will give you some info about server in real time.");
					print.println("quit                - closes telnet session.");
					print.println("");
				} else if (userCommand.equals("status")) {
					// TODO: enhance the output
					print.println("Registered Server Count: " + GameServerTable.getInstance().getRegisteredGameServers().size());
				} else if (userCommand.startsWith("unblock")) {
					try {
						userCommand = userCommand.substring(8);
						if (LoginController.getInstance().removeBanForAddress(userCommand)) {
							LOG.warn("IP removed via TELNET by host {}!", clientSocket.getInetAddress().getHostAddress());
							print.println("The IP " + userCommand + " has been removed from the hack protection list!");
						} else {
							print.println("IP not found in hack protection list...");
						}
					} catch (StringIndexOutOfBoundsException e) {
						print.println("Please Enter the IP to Unblock!");
					}
				} else if (userCommand.startsWith("shutdown")) {
					LoginServer.getInstance().shutdown(false);
					print.println("Bye Bye!");
					print.flush();
					clientSocket.close();
				} else if (userCommand.startsWith("restart")) {
					LoginServer.getInstance().shutdown(true);
					print.println("Bye Bye!");
					print.flush();
					clientSocket.close();
				} else if (userCommand.equals("RedirectLogger")) {
					redirectLogger = true;
				} else if (userCommand.equals("quit")) { /* Do Nothing :p - Just here to save us from the "Command Not Understood" Text */
				} else if (userCommand.isEmpty()) { /* Do Nothing Again - Same reason as the quit part */
				} else {
					print.println("Invalid Command");
				}
				print.print("");
				print.flush();
			}
			if (!clientSocket.isClosed()) {
				print.println("Bye Bye!");
				print.flush();
				clientSocket.close();
			}
			telnetOutput(1, "Connection from " + clientSocket.getInetAddress().getHostAddress() + " was closed by client.");
		} catch (Exception ex) {
			LOG.warn("There has been an error executing login status task!", ex);
		}
	}

	public void printToTelnet(String msg) {
		synchronized (print) {
			print.println(msg);
			print.flush();
		}
	}

	public boolean isRedirectLogger() {
		return redirectLogger;
	}
}
