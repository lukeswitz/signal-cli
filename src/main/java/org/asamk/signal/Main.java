/*
  Copyright (C) 2015-2022 AsamK and contributors

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.asamk.signal;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.DefaultSettings;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

import org.asamk.signal.commands.exceptions.CommandException;
import org.asamk.signal.commands.exceptions.IOErrorException;
import org.asamk.signal.commands.exceptions.UnexpectedErrorException;
import org.asamk.signal.commands.exceptions.UntrustedKeyErrorException;
import org.asamk.signal.commands.exceptions.UserErrorException;
import org.asamk.signal.logging.LogConfigurator;
import org.asamk.signal.manager.ManagerLogger;
import org.asamk.signal.util.SecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.io.File;
import java.security.Security;

public class Main {

    public static void main(String[] args) {
        // enable unlimited strength crypto via Policy, supported on relevant JREs
        Security.setProperty("crypto.policy", "unlimited");
        installSecurityProviderWorkaround();

        // Configuring the logger needs to happen before any logger is initialized
    private static final TimeZone tzUTC = TimeZone.getTimeZone("UTC");

    private Context mContext;
    private File mFileHome;
    private Manager m;
        final var nsLog = parseArgs(args);
        final var verboseLevel = nsLog == null ? 0 : nsLog.getInt("verbose");
        final var logFile = nsLog == null ? null : nsLog.<File>get("log-file");
        final var scrubLog = nsLog != null && nsLog.getBoolean("scrub-log");
        configureLogging(verboseLevel, logFile, scrubLog);

        var parser = App.buildArgumentParser();

        mContext = context;
        mFileHome = new File(mContext.getFilesDir(),"Signal");
        if (!mFileHome.exists())
            mFileHome.mkdirs();
    }
        var ns = parser.parseArgsOrFail(args);

    public boolean userExists (String username)
    {
        String settingsPath = mFileHome.getPath();
        if (m == null)
            m = new Manager(username, settingsPath);

        boolean result = m.userExists();
        return result;
    }

    public boolean isRegistered (String username)
    {
        String settingsPath = mFileHome.getPath();
        if (m == null)
            m = new Manager(username, settingsPath);

        boolean result = m.isRegistered();
        return result;
    }

    public void resetUser ()
    {
        deleteRecursive(mFileHome);
    }

    private void deleteRecursive(File fileOrDirectory) {
        if (fileOrDirectory.isDirectory())
            for (File child : fileOrDirectory.listFiles())
                deleteRecursive(child);

        fileOrDirectory.delete();
    }

    public int handleCommands(Namespace ns) {
        final String username = ns.getString("username");
        Signal ts;
        int status = 0;
        try {
            new App(ns).init();
        } catch (CommandException e) {
            System.err.println(e.getMessage());
            if (verboseLevel > 0 && e.getCause() != null) {
                e.getCause().printStackTrace();
            }


            switch (ns.getString("command")) {
                case "register":
                    if (!m.userHasKeys()) {
                        m.createNewIdentity();
                    }
                    try {
                        m.register(ns.getBoolean("voice"));
                    } catch (IOException e) {
                        System.err.println("Request verify error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "unregister":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.unregister();
                    } catch (IOException e) {
                        System.err.println("Unregister error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "updateAccount":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.updateAccountAttributes();
                    } catch (IOException e) {
                        System.err.println("UpdateAccount error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "setPin":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        String registrationLockPin = ns.getString("registrationLockPin");
                        m.setRegistrationLockPin(Optional.of(registrationLockPin));
                    } catch (IOException e) {
                        System.err.println("Set pin error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "removePin":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.setRegistrationLockPin(Optional.<String>absent());
                    } catch (IOException e) {
                        System.err.println("Remove pin error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "verify":
                    if (!m.userHasKeys()) {
                        System.err.println("User has no keys, first call register.");
                        return 1;
                    }
                    if (m.isRegistered()) {
                        System.err.println("User registration is already verified");
                        return 1;
                    }
                    try {
                        String verificationCode = ns.getString("verificationCode");
                        String pin = ns.getString("pin");
                        m.verifyAccount(verificationCode, pin);
                    } catch (LockedException e) {
                        System.err.println("Verification failed! This number is locked with a pin. Hours remaining until reset: " + (e.getTimeRemaining() / 1000 / 60 / 60));
                        System.err.println("Use '--pin PIN_CODE' to specify the registration lock PIN");
                        return 3;
                    } catch (IOException e) {
                        System.err.println("Verify error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "link":

                    // When linking, username is null and we always have to create keys
                    m.createNewIdentity();

                    String deviceName = ns.getString("name");
                    if (deviceName == null) {
                        deviceName = "cli";
                    }
                    try {
                        System.out.println(m.getDeviceLinkUri());
                        m.finishDeviceLink(deviceName);
                        System.out.println("Associated with: " + m.getUsername());
                    } catch (TimeoutException e) {
                        System.err.println("Link request timed out, please try again.");
                        return 3;
                    } catch (IOException e) {
                        System.err.println("Link request error: " + e.getMessage());
                        return 3;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                        return 2;
                    } catch (UserAlreadyExists e) {
                        System.err.println("The user " + e.getUsername() + " already exists\nDelete \"" + e.getFileName() + "\" before trying again.");
                        return 1;
                    }
                    break;
                case "addDevice":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.addDeviceLink(new URI(ns.getString("uri")));
                    } catch (IOException e) {
                        e.printStackTrace();
                        return 3;
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                        return 2;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                        return 2;
                    }
                    break;
                case "listDevices":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        List<DeviceInfo> devices = m.getLinkedDevices();
                        for (DeviceInfo d : devices) {
                            System.out.println("Device " + d.getId() + (d.getId() == m.getDeviceId() ? " (this device)" : "") + ":");
                            System.out.println(" Name: " + d.getName());
                            System.out.println(" Created: " + formatTimestamp(d.getCreated()));
                            System.out.println(" Last seen: " + formatTimestamp(d.getLastSeen()));
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        return 3;
                    }
                    break;
                case "removeDevice":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        int deviceId = ns.getInt("deviceId");
                        m.removeLinkedDevices(deviceId);
                    } catch (IOException e) {
                        e.printStackTrace();
                        return 3;
                    }
                    break;
                case "send":

                    if (ns.getBoolean("endsession")) {
                        if (ns.getList("recipient") == null) {
                            System.err.println("No recipients given");
                            System.err.println("Aborting sending.");
                            return 1;
                        }
                        try {
                            ts.sendEndSessionMessage(ns.<String>getList("recipient"));
                        } catch (IOException e) {
                            handleIOException(e);
                            return 3;
                        } catch (EncapsulatedExceptions e) {
                            handleEncapsulatedExceptions(e);
                            return 3;
                        } catch (AssertionError e) {
                            handleAssertionError(e);
                            return 1;
                        }
                    } else {
                        String messageText = ns.getString("message");
                        if (messageText == null) {
                            try {
                                messageText = readAll(System.in);
                            } catch (IOException e) {
                                System.err.println("Failed to read message from stdin: " + e.getMessage());
                                System.err.println("Aborting sending.");
                                return 1;
                            }
                        }

                        try {
                            List<String> attachments = ns.getList("attachment");
                            if (attachments == null) {
                                attachments = new ArrayList<>();
                            }
                            if (ns.getString("group") != null) {
                                byte[] groupId = decodeGroupId(ns.getString("group"));
                                ts.sendGroupMessage(messageText, attachments, groupId);
                            } else {
                                ts.sendMessage(messageText, attachments, ns.<String>getList("recipient"));
                            }
                        } catch (IOException e) {
                            handleIOException(e);
                            return 3;
                        } catch (EncapsulatedExceptions e) {
                            handleEncapsulatedExceptions(e);
                            return 3;
                        } catch (AssertionError e) {
                            handleAssertionError(e);
                            return 1;
                        } catch (GroupNotFoundException e) {
                            handleGroupNotFoundException(e);
                            return 1;
                        } catch (AttachmentInvalidException e) {
                            System.err.println("Failed to add attachment: " + e.getMessage());
                            System.err.println("Aborting sending.");
                            return 1;
                        } catch (NotAGroupMemberException e) {
                            e.printStackTrace();
                        }
                    }

                    break;
                case "receive":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    double timeout = 5;
                    if (ns.getDouble("timeout") != null) {
                        timeout = ns.getDouble("timeout");
                    }
                    boolean returnOnTimeout = true;
                    if (timeout < 0) {
                        returnOnTimeout = false;
                        timeout = 3600;
                    }
                    boolean ignoreAttachments = ns.getBoolean("ignore_attachments");
                    try {
                        final Manager.ReceiveMessageHandler handler = ns.getBoolean("json") ? new JsonReceiveMessageHandler(m) : new ReceiveMessageHandler(m);
                        m.receiveMessages((long) (timeout * 1000), TimeUnit.MILLISECONDS, returnOnTimeout, ignoreAttachments, handler);
                    } catch (IOException e) {
                        System.err.println("Error while receiving messages: " + e.getMessage());
                        return 3;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    }
                    break;
                case "quitGroup":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }

                    try {
                        m.sendQuitGroupMessage(decodeGroupId(ns.getString("group")));
                    } catch (IOException e) {
                        handleIOException(e);
                        return 3;
                    } catch (EncapsulatedExceptions e) {
                        handleEncapsulatedExceptions(e);
                        return 3;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    break;
                case "updateGroup":


                    try {
                        byte[] groupId = null;
                        if (ns.getString("group") != null) {
                            groupId = decodeGroupId(ns.getString("group"));
                        }
                        if (groupId == null) {
                            groupId = new byte[0];
                        }
                        String groupName = ns.getString("name");
                        if (groupName == null) {
                            groupName = "";
                        }
                        List<String> groupMembers = ns.<String>getList("member");
                        if (groupMembers == null) {
                            groupMembers = new ArrayList<String>();
                        }
                        String groupAvatar = ns.getString("avatar");
                        if (groupAvatar == null) {
                            groupAvatar = "";
                        }
                        byte[] newGroupId = ts.updateGroup(groupId, groupName, groupMembers, groupAvatar);
                        if (groupId.length != newGroupId.length) {
                            System.out.println("Creating new group \"" + Base64.encodeBytes(newGroupId) + "\" …");
                        }
                    } catch (IOException e) {
                        handleIOException(e);
                        return 3;
                    }

                    /**catch (AttachmentInvalidException e) {
                        System.err.println("Failed to add avatar attachment for group\": " + e.getMessage());
                        System.err.println("Aborting sending.");
                        return 1;
                    } catch (GroupNotFoundException e) {
                        handleGroupNotFoundException(e);
                        return 1;
                    } catch (NotAGroupMemberException e) {
                        handleNotAGroupMemberException(e);
                        return 1;
                     **/
                     catch (EncapsulatedExceptions e) {
                        handleEncapsulatedExceptions(e);
                        return 3;
                    }
                    catch (Exception e) {
                        e.printStackTrace();
                        return 3;
                    }

                    break;
                case "listGroups":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }

                    List<GroupInfo> groups = m.getGroups();
                    boolean detailed = ns.getBoolean("detailed");

                    for (GroupInfo group : groups) {
                        printGroup(group, detailed);
                    }
                    break;
                case "listIdentities":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    if (ns.get("number") == null) {
                        for (Map.Entry<String, List<JsonIdentityKeyStore.Identity>> keys : m.getIdentities().entrySet()) {
                            for (JsonIdentityKeyStore.Identity id : keys.getValue()) {
                                printIdentityFingerprint(m, keys.getKey(), id);
                            }
                        }
                    } else {
                        String number = ns.getString("number");
                        for (JsonIdentityKeyStore.Identity id : m.getIdentities(number)) {
                            printIdentityFingerprint(m, number, id);
                        }
                    }
                    break;
                case "trust":

                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    String number = ns.getString("number");
                    if (ns.getBoolean("trust_all_known_keys")) {
                        boolean res = m.trustIdentityAllKeys(number);
                        if (!res) {
                            System.err.println("Failed to set the trust for this number, make sure the number is correct.");
                            return 1;
                        }
                    } else {
                        String fingerprint = ns.getString("verified_fingerprint");
                        if (fingerprint != null) {
                            fingerprint = fingerprint.replaceAll(" ", "");
                            if (fingerprint.length() == 66) {
                                byte[] fingerprintBytes;
                                try {
                                    fingerprintBytes = Hex.toByteArray(fingerprint.toLowerCase(Locale.ROOT));
                                } catch (Exception e) {
                                    System.err.println("Failed to parse the fingerprint, make sure the fingerprint is a correctly encoded hex string without additional characters.");
                                    return 1;
                                }
                                boolean res = m.trustIdentityVerified(number, fingerprintBytes);
                                if (!res) {
                                    System.err.println("Failed to set the trust for the fingerprint of this number, make sure the number and the fingerprint are correct.");
                                    return 1;
                                }
                            } else if (fingerprint.length() == 60) {
                                boolean res = m.trustIdentityVerifiedSafetyNumber(number, fingerprint);
                                if (!res) {
                                    System.err.println("Failed to set the trust for the safety number of this phone number, make sure the phone number and the safety number are correct.");
                                    return 1;
                                }
                            } else {
                                System.err.println("Fingerprint has invalid format, either specify the old hex fingerprint or the new safety number");
                                return 1;
                            }
                        } else {
                            System.err.println("You need to specify the fingerprint you have verified with -v FINGERPRINT");
                            return 1;
                        }
                    }
                    break;

            }
            return 0;
        } finally {

        }
        System.exit(status);
    }

    private static void installSecurityProviderWorkaround() {
        // Register our own security provider
        Security.insertProviderAt(new SecurityProvider(), 1);
        Security.addProvider(new BouncyCastleProvider());
    }

    private static Namespace parseArgs(String[] args) {
        var parser = ArgumentParsers.newFor("signal-cli", DefaultSettings.VERSION_0_9_0_DEFAULT_SETTINGS)
                .includeArgumentNamesAsKeysInResult(true)
                .build()
                .defaultHelp(false);
        parser.addArgument("-v", "--verbose").action(Arguments.count());
        parser.addArgument("--log-file").type(File.class);
        parser.addArgument("--scrub-log").action(Arguments.storeTrue());

        try {
            return parser.parseKnownArgs(args, null);
        } catch (ArgumentParserException e) {
            return null;
        }
    }

    private static void configureLogging(final int verboseLevel, final File logFile, final boolean scrubLog) {
        LogConfigurator.setVerboseLevel(verboseLevel);
        LogConfigurator.setLogFile(logFile);
        LogConfigurator.setScrubSensitiveInformation(scrubLog);

        if (verboseLevel > 0) {
            java.util.logging.Logger.getLogger("")
                    .setLevel(verboseLevel > 2 ? java.util.logging.Level.FINEST : java.util.logging.Level.INFO);
            ManagerLogger.initLogger();
        }
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    private static int getStatusForError(final CommandException e) {
        if (e instanceof UserErrorException) {
            return 1;
        } else if (e instanceof UnexpectedErrorException) {
            return 2;
        } else if (e instanceof IOErrorException) {
            return 3;
        } else if (e instanceof UntrustedKeyErrorException) {
            return 4;
        } else {
            return 2;
        }
    }

    private static class ReceiveMessageHandler implements Manager.ReceiveMessageHandler {
        final Manager m;

        public ReceiveMessageHandler(Manager m) {
            this.m = m;
        }

        @Override
        public void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent content, Throwable exception) {
            SignalServiceAddress source = envelope.getSourceAddress();
            ContactInfo sourceContact = m.getContact(source.getNumber());
            System.out.println(String.format("Envelope from: %s (device: %d)", (sourceContact == null ? "" : "“" + sourceContact.name + "” ") + source.getNumber(), envelope.getSourceDevice()));
            if (source.getRelay().isPresent()) {
                System.out.println("Relayed by: " + source.getRelay().get());
            }
            System.out.println("Timestamp: " + formatTimestamp(envelope.getTimestamp()));

            if (envelope.isReceipt()) {
                System.out.println("Got receipt.");
            } else if (envelope.isSignalMessage() | envelope.isPreKeySignalMessage()) {
                if (exception != null) {
                    if (exception instanceof org.whispersystems.libsignal.UntrustedIdentityException) {
                        org.whispersystems.libsignal.UntrustedIdentityException e = (org.whispersystems.libsignal.UntrustedIdentityException) exception;
                        System.out.println("The user’s key is untrusted, either the user has reinstalled Signal or a third party sent this message.");
                        System.out.println("Use 'signal-cli -u " + m.getUsername() + " listIdentities -n " + e.getName() + "', verify the key and run 'signal-cli -u " + m.getUsername() + " trust -v \"FINGER_PRINT\" " + e.getName() + "' to mark it as trusted");
                        System.out.println("If you don't care about security, use 'signal-cli -u " + m.getUsername() + " trust -a " + e.getName() + "' to trust it without verification");
                    } else {
                        System.out.println("Exception: " + exception.getMessage() + " (" + exception.getClass().getSimpleName() + ")");
                    }
                }
                if (content == null) {
                    System.out.println("Failed to decrypt message.");
                } else {
                    if (content.getDataMessage().isPresent()) {
                        SignalServiceDataMessage message = content.getDataMessage().get();
                        handleSignalServiceDataMessage(message);
                    }
                    if (content.getSyncMessage().isPresent()) {
                        System.out.println("Received a sync message");
                        SignalServiceSyncMessage syncMessage = content.getSyncMessage().get();

                        if (syncMessage.getContacts().isPresent()) {
                            final ContactsMessage contactsMessage = syncMessage.getContacts().get();
                            if (contactsMessage.isComplete()) {
                                System.out.println("Received complete sync contacts");
                            } else {
                                System.out.println("Received sync contacts");
                            }
                            printAttachment(contactsMessage.getContactsStream());
                        }
                        if (syncMessage.getGroups().isPresent()) {
                            System.out.println("Received sync groups");
                            printAttachment(syncMessage.getGroups().get());
                        }
                        if (syncMessage.getRead().isPresent()) {
                            System.out.println("Received sync read messages list");
                            for (ReadMessage rm : syncMessage.getRead().get()) {
                                ContactInfo fromContact = m.getContact(rm.getSender());
                                System.out.println("From: " + (fromContact == null ? "" : "“" + fromContact.name + "” ") + rm.getSender() + " Message timestamp: " + formatTimestamp(rm.getTimestamp()));
                            }
                        }
                        if (syncMessage.getRequest().isPresent()) {
                            System.out.println("Received sync request");
                            if (syncMessage.getRequest().get().isContactsRequest()) {
                                System.out.println(" - contacts request");
                            }
                            if (syncMessage.getRequest().get().isGroupsRequest()) {
                                System.out.println(" - groups request");
                            }
                        }
                        if (syncMessage.getSent().isPresent()) {
                            System.out.println("Received sync sent message");
                            final SentTranscriptMessage sentTranscriptMessage = syncMessage.getSent().get();
                            String to;
                            if (sentTranscriptMessage.getDestination().isPresent()) {
                                String dest = sentTranscriptMessage.getDestination().get();
                                ContactInfo destContact = m.getContact(dest);
                                to = (destContact == null ? "" : "“" + destContact.name + "” ") + dest;
                            } else {
                                to = "Unknown";
                            }
                            System.out.println("To: " + to + " , Message timestamp: " + formatTimestamp(sentTranscriptMessage.getTimestamp()));
                            if (sentTranscriptMessage.getExpirationStartTimestamp() > 0) {
                                System.out.println("Expiration started at: " + formatTimestamp(sentTranscriptMessage.getExpirationStartTimestamp()));
                            }
                            SignalServiceDataMessage message = sentTranscriptMessage.getMessage();
                            handleSignalServiceDataMessage(message);
                        }
                        if (syncMessage.getBlockedList().isPresent()) {
                            System.out.println("Received sync message with block list");
                            System.out.println("Blocked numbers:");
                            final BlockedListMessage blockedList = syncMessage.getBlockedList().get();
                            for (String number : blockedList.getNumbers()) {
                                System.out.println(" - " + number);
                            }
                        }
                        if (syncMessage.getVerified().isPresent()) {
                            System.out.println("Received sync message with verified identities:");
                            final VerifiedMessage verifiedMessage = syncMessage.getVerified().get();
                            System.out.println(" - " + verifiedMessage.getDestination() + ": " + verifiedMessage.getVerified());
                            String safetyNumber = formatSafetyNumber(m.computeSafetyNumber(verifiedMessage.getDestination(), verifiedMessage.getIdentityKey()));
                            System.out.println("   " + safetyNumber);
                        }
                        if (syncMessage.getConfiguration().isPresent()) {
                            System.out.println("Received sync message with configuration:");
                            final ConfigurationMessage configurationMessage = syncMessage.getConfiguration().get();
                            if (configurationMessage.getReadReceipts().isPresent()) {
                                System.out.println(" - Read receipts: " + (configurationMessage.getReadReceipts().get() ? "enabled" : "disabled"));
                            }
                        }
                    }
                    if (content.getCallMessage().isPresent()) {
                        System.out.println("Received a call message");
                        SignalServiceCallMessage callMessage = content.getCallMessage().get();
                        if (callMessage.getAnswerMessage().isPresent()) {
                            AnswerMessage answerMessage = callMessage.getAnswerMessage().get();
                            System.out.println("Answer message: " + answerMessage.getId() + ": " + answerMessage.getDescription());
                        }
                        if (callMessage.getBusyMessage().isPresent()) {
                            BusyMessage busyMessage = callMessage.getBusyMessage().get();
                            System.out.println("Busy message: " + busyMessage.getId());
                        }
                        if (callMessage.getHangupMessage().isPresent()) {
                            HangupMessage hangupMessage = callMessage.getHangupMessage().get();
                            System.out.println("Hangup message: " + hangupMessage.getId());
                        }
                        if (callMessage.getIceUpdateMessages().isPresent()) {
                            List<IceUpdateMessage> iceUpdateMessages = callMessage.getIceUpdateMessages().get();
                            for (IceUpdateMessage iceUpdateMessage : iceUpdateMessages) {
                                System.out.println("Ice update message: " + iceUpdateMessage.getId() + ", sdp: " + iceUpdateMessage.getSdp());
                            }
                        }
                        if (callMessage.getOfferMessage().isPresent()) {
                            OfferMessage offerMessage = callMessage.getOfferMessage().get();
                            System.out.println("Offer message: " + offerMessage.getId() + ": " + offerMessage.getDescription());
                        }
                    }
                    if (content.getReceiptMessage().isPresent()) {
                        System.out.println("Received a receipt message");
                        SignalServiceReceiptMessage receiptMessage = content.getReceiptMessage().get();
                        System.out.println(" - When: " + formatTimestamp(receiptMessage.getWhen()));
                        if (receiptMessage.isDeliveryReceipt()) {
                            System.out.println(" - Is delivery receipt");
                        }
                        if (receiptMessage.isReadReceipt()) {
                            System.out.println(" - Is read receipt");
                        }
                        System.out.println(" - Timestamps:");
                        for (long timestamp : receiptMessage.getTimestamps()) {
                            System.out.println("    " + formatTimestamp(timestamp));
                        }
                    }
                }
            } else {
                System.out.println("Unknown message received.");
            }
            System.out.println();
        }

        private void handleSignalServiceDataMessage(SignalServiceDataMessage message) {
            System.out.println("Message timestamp: " + formatTimestamp(message.getTimestamp()));

            if (message.getBody().isPresent()) {
                System.out.println("Body: " + message.getBody().get());
            }
            if (message.getGroupInfo().isPresent()) {
                SignalServiceGroup groupInfo = message.getGroupInfo().get();
                System.out.println("Group info:");
                System.out.println("  Id: " + Base64.encodeBytes(groupInfo.getGroupId()));
                if (groupInfo.getType() == SignalServiceGroup.Type.UPDATE && groupInfo.getName().isPresent()) {
                    System.out.println("  Name: " + groupInfo.getName().get());
                } else {
                    GroupInfo group = m.getGroup(groupInfo.getGroupId());
                    if (group != null) {
                        System.out.println("  Name: " + group.name);
                    } else {
                        System.out.println("  Name: <Unknown group>");
                    }
                }
                System.out.println("  Type: " + groupInfo.getType());
                if (groupInfo.getMembers().isPresent()) {
                    for (String member : groupInfo.getMembers().get()) {
                        System.out.println("  Member: " + member);
                    }
                }
                if (groupInfo.getAvatar().isPresent()) {
                    System.out.println("  Avatar:");
                    printAttachment(groupInfo.getAvatar().get());
                }
            }
            if (message.isEndSession()) {
                System.out.println("Is end session");
            }
            if (message.isExpirationUpdate()) {
                System.out.println("Is Expiration update: " + message.isExpirationUpdate());
            }
            if (message.getExpiresInSeconds() > 0) {
                System.out.println("Expires in: " + message.getExpiresInSeconds() + " seconds");
            }
            if (message.isProfileKeyUpdate() && message.getProfileKey().isPresent()) {
                System.out.println("Profile key update, key length:" + message.getProfileKey().get().length);
            }

            if (message.getQuote().isPresent()) {
                SignalServiceDataMessage.Quote quote = message.getQuote().get();
                System.out.println("Quote: (" + quote.getId() + ")");
                System.out.println(" Author: " + quote.getAuthor().getNumber());
                System.out.println(" Text: " + quote.getText());
                if (quote.getAttachments().size() > 0) {
                    System.out.println(" Attachments: ");
                    for (SignalServiceDataMessage.Quote.QuotedAttachment attachment : quote.getAttachments()) {
                        System.out.println("  Filename: " + attachment.getFileName());
                        System.out.println("  Type: " + attachment.getContentType());
                        System.out.println("  Thumbnail:");
                        printAttachment(attachment.getThumbnail());
                    }
                }
            }

            if (message.getAttachments().isPresent()) {
                System.out.println("Attachments: ");
                for (SignalServiceAttachment attachment : message.getAttachments().get()) {
                    printAttachment(attachment);
                }
            }
        }

        private void printAttachment(SignalServiceAttachment attachment) {
            System.out.println("- " + attachment.getContentType() + " (" + (attachment.isPointer() ? "Pointer" : "") + (attachment.isStream() ? "Stream" : "") + ")");
            if (attachment.isPointer()) {
                final SignalServiceAttachmentPointer pointer = attachment.asPointer();
                System.out.println("  Id: " + pointer.getId() + " Key length: " + pointer.getKey().length + (pointer.getRelay().isPresent() ? " Relay: " + pointer.getRelay().get() : ""));
                System.out.println("  Filename: " + (pointer.getFileName().isPresent() ? pointer.getFileName().get() : "-"));
                System.out.println("  Size: " + (pointer.getSize().isPresent() ? pointer.getSize().get() + " bytes" : "<unavailable>") + (pointer.getPreview().isPresent() ? " (Preview is available: " + pointer.getPreview().get().length + " bytes)" : ""));
                System.out.println("  Voice note: " + (pointer.getVoiceNote() ? "yes" : "no"));
                System.out.println("  Dimensions: " + pointer.getWidth() + "x" + pointer.getHeight());
                File file = m.getAttachmentFile(pointer.getId());
                if (file.exists()) {
                    System.out.println("  Stored plaintext in: " + file);
                }
            }
        }
    }



    private static class JsonReceiveMessageHandler implements Manager.ReceiveMessageHandler {
        final Manager m;
        final ObjectMapper jsonProcessor;

        public JsonReceiveMessageHandler(Manager m) {
            this.m = m;
            this.jsonProcessor = new ObjectMapper();
            jsonProcessor.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY); // disable autodetect
            jsonProcessor.enable(SerializationFeature.WRITE_NULL_MAP_VALUES);
            jsonProcessor.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            jsonProcessor.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
        }

        @Override
        public void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent content, Throwable exception) {
            ObjectNode result = jsonProcessor.createObjectNode();
            if (exception != null) {
                result.putPOJO("error", new JsonError(exception));
            }
            if (envelope != null) {
                result.putPOJO("envelope", new JsonMessageEnvelope(envelope, content));
            }
            try {
                jsonProcessor.writeValue(System.out, result);
                System.out.println();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static String formatTimestamp(long timestamp) {
        Date date = new Date(timestamp);
        final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
        df.setTimeZone(tzUTC);
        return timestamp + " (" + df.format(date) + ")";
    }
}
