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
package com.l2jserver.loginserver.network.serverpackets;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.l2jserver.loginserver.GameServerTable;
import com.l2jserver.loginserver.GameServerTable.GameServerInfo;
import com.l2jserver.loginserver.network.L2LoginClient;
import com.l2jserver.loginserver.network.gameserverpackets.ServerStatus;

/**
 * Server will be considered as good when the number of online players is less than half the maximum,<br>
 * as Normal between half and 4/5 and Full when there's more than 4/5 of the maximum number of players.
 * 
 * <pre>
 * Format: cc [cddcchhcdc]
 * 
 * c: server list size (number of servers)
 * c: ?
 * [ (repeat for each servers)
 * c: server id (ignored by client?)
 * d: server ip
 * d: server port
 * c: age limit (used by client?)
 * c: pvp or not (used by client?)
 * h: current number of players
 * h: max number of players
 * c: 0 if server is down
 * d: 2nd bit: clock
 *    3rd bit: won't display server name
 *    4th bit: test server (used by client?)
 * c: 0 if you don't want to display brackets in front of sever name
 * ]
 * </pre>
 * 
 * @version 2.6.1.0
 */
public final class ServerList extends L2LoginServerPacket {

	private static final Logger LOG = LoggerFactory.getLogger(ServerList.class);

	private final List<ServerData> servers;
	private final int lastServer;
	private final Map<Integer, Integer> charsOnServers;
	private final Map<Integer, long[]> charsToDelete;

	static class ServerData {
		protected byte[] ip;
		protected final int port;
		protected final int ageLimit;
		protected final boolean pvp;
		protected final int currentPlayers;
		protected final int maxPlayers;
		protected final boolean brackets;
		protected boolean clock;
		protected final int status;
		protected final int serverId;
		protected final int serverType;

		ServerData(L2LoginClient client, GameServerInfo gsi) {
			try {
				ip = InetAddress.getByName(gsi.getServerAddress(client.getConnection().getInetAddress())).getAddress();
			} catch (UnknownHostException ex) {
				LOG.warn("There has been an error getting IP from host!", ex);
				ip = new byte[4];
				ip[0] = 127;
				ip[1] = 0;
				ip[2] = 0;
				ip[3] = 1;
			}

			port = gsi.getPort();
			pvp = gsi.isPvp();
			serverType = gsi.getServerType();
			currentPlayers = gsi.getCurrentPlayerCount();
			maxPlayers = gsi.getMaxPlayers();
			ageLimit = 0;
			brackets = gsi.isShowingBrackets();
			// If server GM-only - show status only to GMs
			status = gsi.getStatus() != ServerStatus.STATUS_GM_ONLY ? gsi.getStatus() : client.getAccessLevel() > 0 ? gsi.getStatus() : ServerStatus.STATUS_DOWN;
			serverId = gsi.getId();
		}
	}

	public ServerList(L2LoginClient client) {
		servers = new ArrayList<>(GameServerTable.getInstance().getRegisteredGameServers().size());
		lastServer = client.getLastServer();
		for (GameServerInfo gsi : GameServerTable.getInstance().getRegisteredGameServers().values()) {
			servers.add(new ServerData(client, gsi));
		}
		charsOnServers = client.getCharsOnServ();
		charsToDelete = client.getCharsWaitingDelOnServ();
	}

	@Override
	public void write() {
		writeC(0x04);
		writeC(servers.size());
		writeC(lastServer);
		for (ServerData server : servers) {
			writeC(server.serverId); // server id

			writeC(server.ip[0] & 0xff);
			writeC(server.ip[1] & 0xff);
			writeC(server.ip[2] & 0xff);
			writeC(server.ip[3] & 0xff);

			writeD(server.port);
			writeC(server.ageLimit); // Age Limit 0, 15, 18
			writeC(server.pvp ? 0x01 : 0x00);
			writeH(server.currentPlayers);
			writeH(server.maxPlayers);
			writeC(server.status == ServerStatus.STATUS_DOWN ? 0x00 : 0x01);
			writeD(server.serverType); // 1: Normal, 2: Relax, 4: Public Test, 8: No Label, 16: Character Creation Restricted, 32: Event, 64: Free
			writeC(server.brackets ? 0x01 : 0x00);
		}
		writeH(0x00); // unknown
		if (charsOnServers != null) {
			writeC(charsOnServers.size());
			for (int servId : charsOnServers.keySet()) {
				writeC(servId);
				writeC(charsOnServers.get(servId));
				if ((charsToDelete == null) || !charsToDelete.containsKey(servId)) {
					writeC(0x00);
				} else {
					writeC(charsToDelete.get(servId).length);
					for (long deleteTime : charsToDelete.get(servId)) {
						writeD((int) ((deleteTime - System.currentTimeMillis()) / 1000));
					}
				}
			}
		} else {
			writeC(0x00);
		}
	}
}
