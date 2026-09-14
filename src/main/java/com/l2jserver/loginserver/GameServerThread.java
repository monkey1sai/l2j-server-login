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
import static com.l2jserver.loginserver.network.loginserverpackets.LoginServerFail.REASON_IP_BANNED;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.l2jserver.commons.dao.ServerNameDAO;
import com.l2jserver.commons.network.BaseSendablePacket;
import com.l2jserver.commons.security.crypt.NewCrypt;
import com.l2jserver.commons.util.Util;
import com.l2jserver.loginserver.GameServerTable.GameServerInfo;
import com.l2jserver.loginserver.network.L2JGameServerPacketHandler;
import com.l2jserver.loginserver.network.L2JGameServerPacketHandler.GameServerState;
import com.l2jserver.loginserver.network.loginserverpackets.ChangePasswordResponse;
import com.l2jserver.loginserver.network.loginserverpackets.InitLS;
import com.l2jserver.loginserver.network.loginserverpackets.KickPlayer;
import com.l2jserver.loginserver.network.loginserverpackets.LoginServerFail;
import com.l2jserver.loginserver.network.loginserverpackets.RequestCharacters;

/**
 * Game Server thread.
 * @author -Wooden-
 * @author KenM
 * @version 2.6.1.0
 */
public class GameServerThread extends Thread {

	private static final Logger LOG = LoggerFactory.getLogger(GameServerThread.class);

	private final Socket connection;

	private InputStream in;

	private OutputStream out;

	private final RSAPublicKey publicKey;

	private final RSAPrivateKey privateKey;

	private NewCrypt blowfish;

	private GameServerState loginConnectionState = GameServerState.CONNECTED;

	private final String connectionIp;

	private GameServerInfo gameServerInfo;

	/** Authenticated clients on the game server. */
	private final Set<String> accountsOnGameServer = ConcurrentHashMap.newKeySet();

	private String connectionIPAddress;

	@Override
	public void run() {
		connectionIPAddress = connection.getInetAddress().getHostAddress();
		if (GameServerThread.isBannedGameServerIP(connectionIPAddress)) {
			LOG.warn("IP Address {} is on banned IP list.", connectionIPAddress);
			forceClose(REASON_IP_BANNED);
			return;
		}

		try {
			sendPacket(new InitLS(publicKey.getModulus().toByteArray()));

			int lengthHi;
			int lengthLo;
			int length;
			boolean checksumOk;
			for (;;) {
				lengthLo = in.read();
				lengthHi = in.read();
				length = (lengthHi * 256) + lengthLo;

				if ((lengthHi < 0) || connection.isClosed()) {
					LOG.warn("Login terminated the connection!");
					break;
				}

				byte[] data = new byte[length - 2];

				int receivedBytes = 0;
				int newBytes = 0;
				int left = length - 2;
				while ((newBytes != -1) && (receivedBytes < (length - 2))) {
					newBytes = in.read(data, receivedBytes, left);
					receivedBytes = receivedBytes + newBytes;
					left -= newBytes;
				}

				if (receivedBytes != (length - 2)) {
					LOG.warn("Incomplete Packet is sent to the server, closing connection. (LS)");
					break;
				}

				// decrypt if we have a key
				blowfish.decrypt(data, 0, data.length);
				checksumOk = NewCrypt.verifyChecksum(data);
				if (!checksumOk) {
					LOG.warn("Incorrect packet checksum, closing connection. (LS)");
					return;
				}

				if (server().isDebug()) {
					LOG.warn("[C]" + System.lineSeparator() + Util.printData(data));
				}

				L2JGameServerPacketHandler.handlePacket(data, this);
			}
		} catch (IOException ex) {
			final var serverName = (getServerId() != -1 ? "[" + getServerId() + "] " + ServerNameDAO.getServer(getServerId()) : "(" + connectionIPAddress + ")");
			LOG.warn("Game Server {} lost connection!", serverName);
			broadcastToTelnet("Game Server " + serverName + " lost connection!");
		} finally {
			if (isAuthed()) {
				gameServerInfo.setDown();

				LOG.info("Server {}[{}] is now disconnected.", ServerNameDAO.getServer(getServerId()), getServerId());
			}
			LoginServer.getInstance().getGameServerListener().removeGameServer(this);
			LoginServer.getInstance().getGameServerListener().removeFloodProtection(connectionIp);
		}
	}

	public boolean hasAccountOnGameServer(String account) {
		return accountsOnGameServer.contains(account);
	}

	public int getPlayerCount() {
		return accountsOnGameServer.size();
	}

	/**
	 * Attaches a GameServerInfo to this Thread.<br>
	 * <ul>
	 * <li>Updates the GameServerInfo values based on GameServerAuth packet</li>
	 * <li><b>Sets the GameServerInfo as Authed</b></li>
	 * </ul>
	 * @param gsi The GameServerInfo to be attached.
	 * @param port the port
	 * @param hosts the hosts
	 * @param maxPlayers the maximum amount of players
	 */
	public void attachGameServerInfo(GameServerInfo gsi, int port, String[] hosts, int maxPlayers) {
		setGameServerInfo(gsi);
		gsi.setGameServerThread(this);
		gsi.setPort(port);
		setGameHosts(hosts);
		gsi.setMaxPlayers(maxPlayers);
		gsi.setAuthed(true);
	}

	public void forceClose(int reason) {
		sendPacket(new LoginServerFail(reason));

		try {
			connection.close();
		} catch (IOException ex) {
			LOG.debug("Failed disconnecting banned server, server already disconnected.");
		}
	}

	public static boolean isBannedGameServerIP(String ipAddress) {
		return false;
	}

	public GameServerThread(Socket con) {
		connection = con;
		connectionIp = con.getInetAddress().getHostAddress();
		try {
			in = connection.getInputStream();
			out = new BufferedOutputStream(connection.getOutputStream());
		} catch (IOException ex) {
			LOG.warn("There has been an error creating a connection!", ex);
		}

		KeyPair pair = GameServerTable.getInstance().getKeyPair();
		privateKey = (RSAPrivateKey) pair.getPrivate();
		publicKey = (RSAPublicKey) pair.getPublic();
		blowfish = new NewCrypt("_;v.]05-31!|+-%xT!^[$\00");
		setName(getClass().getSimpleName() + "-" + threadId() + "@" + connectionIp);
		start();
	}

	public void sendPacket(BaseSendablePacket sl) {
		try {
			byte[] data = sl.getContent();
			NewCrypt.appendChecksum(data);
			if (server().isDebug()) {
				LOG.info("[S] {}:{}{}", sl.getClass().getSimpleName(), System.lineSeparator(), Util.printData(data));
			}
			blowfish.crypt(data, 0, data.length);

			int len = data.length + 2;
			synchronized (out) {
				out.write(len & 0xff);
				out.write((len >> 8) & 0xff);
				out.write(data);
				out.flush();
			}
		} catch (IOException ex) {
			LOG.error("There has been an error while sending packet {}!", sl.getClass().getSimpleName(), ex);
		}
	}

	public void broadcastToTelnet(String msg) {
		if (LoginServer.getInstance().getStatusServer() != null) {
			LoginServer.getInstance().getStatusServer().sendMessageToTelnets(msg);
		}
	}

	public void kickPlayer(String account) {
		sendPacket(new KickPlayer(account));
	}

	public void requestCharacters(String account) {
		sendPacket(new RequestCharacters(account));
	}

	public void ChangePasswordResponse(byte successful, String characterName, String msgToSend) {
		sendPacket(new ChangePasswordResponse(successful, characterName, msgToSend));
	}

	public void setGameHosts(String[] hosts) {
		LOG.info("Updated game server {}[{}] IPs.", ServerNameDAO.getServer(getServerId()), getServerId());

		gameServerInfo.clearServerAddresses();
		for (int i = 0; i < hosts.length; i += 2) {
			try {
				gameServerInfo.addServerAddress(hosts[i], hosts[i + 1]);
			} catch (Exception ex) {
				LOG.warn("There has been an error resolving host name {}!", hosts[i], ex);
			}
		}

		for (String s : gameServerInfo.getServerAddresses()) {
			LOG.info(s);
		}
	}

	public boolean isAuthed() {
		if (getGameServerInfo() == null) {
			return false;
		}
		return getGameServerInfo().isAuthed();
	}

	public void setGameServerInfo(GameServerInfo gsi) {
		gameServerInfo = gsi;
	}

	public GameServerInfo getGameServerInfo() {
		return gameServerInfo;
	}

	public String getConnectionIpAddress() {
		return connectionIPAddress;
	}

	public int getServerId() {
		if (getGameServerInfo() != null) {
			return getGameServerInfo().getId();
		}
		return -1;
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setBlowFish(NewCrypt blowfish) {
		this.blowfish = blowfish;
	}

	public void addAccountOnGameServer(String account) {
		accountsOnGameServer.add(account);
	}

	public void removeAccountOnGameServer(String account) {
		accountsOnGameServer.remove(account);
	}

	public GameServerState getLoginConnectionState() {
		return loginConnectionState;
	}

	public void setLoginConnectionState(GameServerState state) {
		loginConnectionState = state;
	}
}
