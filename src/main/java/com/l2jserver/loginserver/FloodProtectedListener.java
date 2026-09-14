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
package com.l2jserver.loginserver;

import static com.l2jserver.loginserver.config.Configuration.server;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Flood Protected listener.
 * @author -Wooden-
 * @version 2.6.1.0
 */
public abstract class FloodProtectedListener extends Thread {

	private static final Logger LOG = LoggerFactory.getLogger(FloodProtectedListener.class);

	private final Map<String, ForeignConnection> floodProtection = new ConcurrentHashMap<>();

	private final ServerSocket serverSocket;

	public FloodProtectedListener(String listenIp, int port) throws Exception {
		if (listenIp.equals("*")) {
			serverSocket = new ServerSocket(port);
		} else {
			serverSocket = new ServerSocket(port, 50, InetAddress.getByName(listenIp));
		}
	}

	@Override
	public void run() {
		Socket connection;
		while (!isInterrupted()) {
			try {
				connection = serverSocket.accept();
				if (server().isFloodProtectionEnabled()) {
					ForeignConnection foreignConnection = floodProtection.get(connection.getInetAddress().getHostAddress());
					if (foreignConnection != null) {
						foreignConnection.connectionNumber += 1;
						if (((foreignConnection.connectionNumber > server().getFastConnectionLimit())
							&& ((System.currentTimeMillis() - foreignConnection.lastConnection) < server().getNormalConnectionTime()))
							|| ((System.currentTimeMillis() - foreignConnection.lastConnection) < server().getFastConnectionTime())
							|| (foreignConnection.connectionNumber > server().getMaxConnectionPerIP())) {
							foreignConnection.lastConnection = System.currentTimeMillis();
							connection.close();
							foreignConnection.connectionNumber -= 1;
							if (!foreignConnection.isFlooding) {
								LOG.warn("Potential Flood from {}!", connection.getInetAddress().getHostAddress());
							}
							foreignConnection.isFlooding = true;
							continue;
						}
						// if connection was flooding server but now passed the check
						if (foreignConnection.isFlooding) {
							foreignConnection.isFlooding = false;
							LOG.info("Connection {} is not considered as flooding anymore.", connection.getInetAddress().getHostAddress());
						}
						foreignConnection.lastConnection = System.currentTimeMillis();
					} else {
						foreignConnection = new ForeignConnection(System.currentTimeMillis());
						floodProtection.put(connection.getInetAddress().getHostAddress(), foreignConnection);
					}
				}

				addClient(connection);
			} catch (Exception e) {
				if (isInterrupted()) {
					close();
					break;
				}
			}
		}
	}

	/**
	 * Tracks connection attempts from a remote IP address for flood protection.
	 */
	protected static class ForeignConnection {
		public int connectionNumber;
		public long lastConnection;
		public boolean isFlooding = false;

		public ForeignConnection(long time) {
			lastConnection = time;
			connectionNumber = 1;
		}
	}

	public abstract void addClient(Socket s);

	public void removeFloodProtection(String ip) {
		if (!server().isFloodProtectionEnabled()) {
			return;
		}
		ForeignConnection foreignConnection = floodProtection.get(ip);
		if (foreignConnection != null) {
			foreignConnection.connectionNumber -= 1;
			if (foreignConnection.connectionNumber == 0) {
				floodProtection.remove(ip);
			}
		} else {
			LOG.warn("Removing a flood protection for a Game Server ({}) that was not in the connection map???", ip);
		}
	}

	public void close() {
		try {
			serverSocket.close();
		} catch (Exception ex) {
			LOG.warn("There has been an error closing the connection!", ex);
		}
	}
}