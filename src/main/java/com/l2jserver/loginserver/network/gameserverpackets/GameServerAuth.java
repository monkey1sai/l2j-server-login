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
package com.l2jserver.loginserver.network.gameserverpackets;

import static com.l2jserver.loginserver.config.Configuration.server;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.l2jserver.commons.dao.ServerNameDAO;
import com.l2jserver.commons.network.BaseRecievePacket;
import com.l2jserver.loginserver.GameServerTable;
import com.l2jserver.loginserver.GameServerTable.GameServerInfo;
import com.l2jserver.loginserver.GameServerThread;
import com.l2jserver.loginserver.model.GameServerVersion;
import com.l2jserver.loginserver.network.L2JGameServerPacketHandler.GameServerState;
import com.l2jserver.loginserver.network.loginserverpackets.AuthResponse;
import com.l2jserver.loginserver.network.loginserverpackets.LoginServerFail;

/**
 * Game Server Auth packet.
 * 
 * <pre>
 * Format: CCCCHDDBD[S]
 * C server version
 * C desired ID
 * C accept alternative ID
 * C reserve Host
 * H port
 * D max players
 * D hex Id size
 * B hex Id
 * D subnet size
 * [S] subnets
 * </pre>
 * 
 * @author -Wooden-
 * @author Zoey76
 * @version 2.6.1.0
 */
public class GameServerAuth extends BaseRecievePacket {

	private static final Logger LOG = LoggerFactory.getLogger(GameServerAuth.class);

	private final GameServerThread server;

	private final byte[] hexId;

	private final int desiredId;

	@SuppressWarnings("unused")
	private final boolean hostReserved;

	private final boolean acceptAlternativeId;

	private final int maxPlayers;

	private final int serverVersion;

	private final int port;

	private final String[] hosts;

	public GameServerAuth(byte[] decrypt, GameServerThread server) {
		super(decrypt);
		this.server = server;
		serverVersion = readC();
		desiredId = readC();
		acceptAlternativeId = (readC() != 0);
		hostReserved = (readC() != 0);
		port = readH();
		maxPlayers = readD();
		int size = readD();
		hexId = readB(size);
		size = 2 * readD();
		hosts = new String[size];
		for (int i = 0; i < size; i++) {
			hosts[i] = readS();
		}

		if (server().isDebug()) {
			LOG.info("Auth request received.");
		}

		if (handleRegProcess()) {
			server.sendPacket(new AuthResponse(server.getGameServerInfo().getId()));
			LOG.info("Game Server {} enabled.", GameServerVersion.valueOf(serverVersion));

			server.broadcastToTelnet("GameServer [" + server.getServerId() + "] " + ServerNameDAO.getServer(server.getServerId()) + " is connected");
			server.setLoginConnectionState(GameServerState.AUTHED);
		}
	}

	private boolean handleRegProcess() {
		if (!server().getServerVersions().contains(serverVersion)) {
			server.forceClose(LoginServerFail.REASON_INVALID_GAME_SERVER_VERSION);
			return false;
		}

		GameServerTable gameServerTable = GameServerTable.getInstance();

		int id = desiredId;
		byte[] hexId = this.hexId;

		GameServerInfo gsi = gameServerTable.getRegisteredGameServerById(id);
		// is there a game server registered with this id?
		if (gsi != null) {
			// does the hex id match?
			if (Arrays.equals(gsi.getHexId(), hexId)) {
				// check to see if this GS is already connected
				synchronized (gsi) {
					if (gsi.isAuthed()) {
						server.forceClose(LoginServerFail.REASON_ALREADY_LOGGED_IN);
						return false;
					}
					server.attachGameServerInfo(gsi, port, hosts, maxPlayers);
				}
			} else {
				// there is already a server registered with the desired id and different hex id
				// try to register this one with an alternative id
				if (server().isAcceptNetGameServer() && acceptAlternativeId) {
					gsi = new GameServerInfo(id, hexId, server);
					if (gameServerTable.registerWithFirstAvailableId(gsi)) {
						server.attachGameServerInfo(gsi, port, hosts, maxPlayers);
						gameServerTable.registerServerOnDB(gsi);
					} else {
						server.forceClose(LoginServerFail.REASON_NO_FREE_ID);
						return false;
					}
				} else {
					// server id is already taken, and we cant get a new one for you
					server.forceClose(LoginServerFail.REASON_WRONG_HEXID);
					return false;
				}
			}
		} else {
			// can we register on this id?
			if (server().isAcceptNetGameServer()) {
				gsi = new GameServerInfo(id, hexId, server);
				if (gameServerTable.register(id, gsi)) {
					server.attachGameServerInfo(gsi, port, hosts, maxPlayers);
					gameServerTable.registerServerOnDB(gsi);
				} else {
					// someone took this ID meanwhile
					server.forceClose(LoginServerFail.REASON_ID_RESERVED);
					return false;
				}
			} else {
				server.forceClose(LoginServerFail.REASON_WRONG_HEXID);
				return false;
			}
		}
		return true;
	}
}
