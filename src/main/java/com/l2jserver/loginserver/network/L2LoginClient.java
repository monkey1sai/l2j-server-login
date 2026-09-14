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
package com.l2jserver.loginserver.network;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.l2jserver.commons.util.Rnd;
import com.l2jserver.loginserver.LoginController;
import com.l2jserver.loginserver.SessionKey;
import com.l2jserver.loginserver.network.serverpackets.L2LoginServerPacket;
import com.l2jserver.loginserver.network.serverpackets.LoginFail;
import com.l2jserver.loginserver.network.serverpackets.LoginFail.LoginFailReason;
import com.l2jserver.loginserver.network.serverpackets.PlayFail;
import com.l2jserver.loginserver.network.serverpackets.PlayFail.PlayFailReason;
import com.l2jserver.loginserver.security.ScrambledKeyPair;
import com.l2jserver.loginserver.security.crypt.LoginCrypt;
import com.l2jserver.mmocore.MMOClient;
import com.l2jserver.mmocore.MMOConnection;
import com.l2jserver.mmocore.SendablePacket;

/**
 * Represents a client connected into the LoginServer.
 * @author KenM
 * @version 2.6.1.0
 */
public final class L2LoginClient extends MMOClient<MMOConnection<L2LoginClient>> {

	private static final Logger LOG = LoggerFactory.getLogger(L2LoginClient.class);

	/**
	 * The authentication state of a connected client.
	 */
	public enum LoginClientState {
		CONNECTED,
		AUTHED_GG,
		AUTHED_LOGIN
	}

	private LoginClientState state;

	private final LoginCrypt loginCrypt;

	private final ScrambledKeyPair scrambledPair;

	private final byte[] blowfishKey;

	private String account;

	private int accessLevel;

	private int lastServer;

	private SessionKey sessionKey;

	private final int sessionId;

	private boolean joinedGS;

	private Map<Integer, Integer> charsOnServers;

	private Map<Integer, long[]> charsToDelete;

	private final long connectionStartTime;

	public L2LoginClient(MMOConnection<L2LoginClient> con) {
		super(con);
		state = LoginClientState.CONNECTED;
		scrambledPair = LoginController.getInstance().getScrambledRSAKeyPair();
		blowfishKey = LoginController.getInstance().getBlowfishKey();
		sessionId = Rnd.nextInt();
		connectionStartTime = System.currentTimeMillis();
		loginCrypt = new LoginCrypt();
		loginCrypt.setKey(blowfishKey);
	}

	@Override
	public boolean decrypt(ByteBuffer buf, int size) {
		try {
			if (!loginCrypt.decrypt(buf.array(), buf.position(), size)) {
				LOG.warn("Wrong checksum from client {}!", this);
				super.getConnection().close((SendablePacket<L2LoginClient>) null);
				return false;
			}
			return true;
		} catch (IOException ex) {
			LOG.warn("There has been an error decrypting message!", ex);
			super.getConnection().close((SendablePacket<L2LoginClient>) null);
			return false;
		}
	}

	@Override
	public boolean encrypt(ByteBuffer buf, int size) {
		final int offset = buf.position();
		try {
			size = loginCrypt.encrypt(buf.array(), offset, size);
		} catch (IOException ex) {
			LOG.warn("There has been an error encrypting message!", ex);
			return false;
		}
		buf.position(offset + size);
		return true;
	}

	public LoginClientState getState() {
		return state;
	}

	public void setState(LoginClientState state) {
		this.state = state;
	}

	public byte[] getBlowfishKey() {
		return blowfishKey;
	}

	public byte[] getScrambledModulus() {
		return scrambledPair.getScrambledModulus();
	}

	public RSAPrivateKey getRSAPrivateKey() {
		return (RSAPrivateKey) scrambledPair.getKeyPair().getPrivate();
	}

	public String getAccount() {
		return account;
	}

	public void setAccount(String account) {
		this.account = account;
	}

	public void setAccessLevel(int accessLevel) {
		this.accessLevel = accessLevel;
	}

	public int getAccessLevel() {
		return accessLevel;
	}

	public void setLastServer(int lastServer) {
		this.lastServer = lastServer;
	}

	public int getLastServer() {
		return lastServer;
	}

	public int getSessionId() {
		return sessionId;
	}

	public boolean hasJoinedGS() {
		return joinedGS;
	}

	public void setJoinedGS(boolean joinedGS) {
		this.joinedGS = joinedGS;
	}

	public void setSessionKey(SessionKey sessionKey) {
		this.sessionKey = sessionKey;
	}

	public SessionKey getSessionKey() {
		return sessionKey;
	}

	public long getConnectionStartTime() {
		return connectionStartTime;
	}

	public void sendPacket(L2LoginServerPacket lsp) {
		getConnection().sendPacket(lsp);
	}

	public void close(LoginFailReason reason) {
		getConnection().close(new LoginFail(reason));
	}

	public void close(PlayFailReason reason) {
		getConnection().close(new PlayFail(reason));
	}

	public void close(L2LoginServerPacket lsp) {
		getConnection().close(lsp);
	}

	public void setCharsOnServ(int servId, int chars) {
		if (charsOnServers == null) {
			charsOnServers = new HashMap<>();
		}
		charsOnServers.put(servId, chars);
	}

	public Map<Integer, Integer> getCharsOnServ() {
		return charsOnServers;
	}

	public void serCharsWaitingDelOnServ(int servId, long[] charsToDel) {
		if (charsToDelete == null) {
			charsToDelete = new HashMap<>();
		}
		charsToDelete.put(servId, charsToDel);
	}

	public Map<Integer, long[]> getCharsWaitingDelOnServ() {
		return charsToDelete;
	}

	@Override
	public void onDisconnection() {
		if (!hasJoinedGS() || ((getConnectionStartTime() + LoginController.LOGIN_TIMEOUT) < System.currentTimeMillis())) {
			LoginController.getInstance().removeAuthedLoginClient(getAccount());
		}
	}

	@Override
	public String toString() {
		InetAddress address = getConnection().getInetAddress();
		if (getState() == LoginClientState.AUTHED_LOGIN) {
			return "[" + getAccount() + " (" + (address == null ? "disconnected" : address.getHostAddress()) + ")]";
		}
		return "[" + (address == null ? "disconnected" : address.getHostAddress()) + "]";
	}

	@Override
	protected void onForcedDisconnection() {
		// Empty
	}
}
