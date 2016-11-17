{-# LANGUAGE OverloadedStrings #-}

import Control.Concurrent (threadDelay)
import Control.Monad (join, unless, forever)
import Data.List (sort)
import qualified Data.Map.Strict as M
import Data.Word (Word32)
import DBus
import DBus.Client
import Gnome.Keyring

agentManager = "org.freedesktop.NetworkManager.AgentManager"
secretAgent  = "org.freedesktop.NetworkManager.SecretAgent"
agentName = "io.broch.NmAgent"

-- | The a{sa{sv}} dbus type used by GetSecrets
type ConnectionHash = M.Map String (M.Map String Variant)

asasv :: Type
asasv = TypeDictionary TypeString (TypeDictionary TypeString TypeVariant)

main = do
    client <- connectSystem
    let kr = keyring "login"

    registerSecretAgent client (keyRingGetConnectionSecret kr)

    forever (threadDelay maxBound)

-- | Export a SecretAgent and register it with NetworkManager
registerSecretAgent client getSecrets = do
    nr <- requestName client agentName [nameAllowReplacement, nameReplaceExisting]
    let emptyReturn = return (replyReturn [])
    export client "/org/freedesktop/NetworkManager/SecretAgent"
        [ autoMethod secretAgent "GetSecrets"
             (doGetSecrets getSecrets)
        , method secretAgent "CancelGetSecrets"
             (signature_ [TypeObjectPath, TypeString])
             (signature_ [])
             (\_ -> print "CancelGetSecrets called" >> emptyReturn)
        , method secretAgent "SaveSecrets"
             (signature_ [asasv, TypeObjectPath])
             (signature_ [])
             (\_ -> print "Someone wants me to save secrets" >> emptyReturn)
        , method secretAgent "DeleteSecrets"
             (signature_ [asasv, TypeObjectPath])
             (signature_ [])
             (\_ -> print "Someone wants me to delete secrets" >> emptyReturn)
        ]

    reply <- call_ client (methodCall "/org/freedesktop/NetworkManager/AgentManager" agentManager "Register")
        { methodCallDestination = Just "org.freedesktop.NetworkManager"
        , methodCallBody = [toVariant agentName]
        }

    return ()

printNames client = do
    -- Request a list of connected clients from the bus
    reply <- call_ client (methodCall "/org/freedesktop/DBus" "org.freedesktop.DBus" "ListNames")
        { methodCallDestination = Just "org.freedesktop.DBus"
        }

    -- org.freedesktop.DBus.ListNames() returns a single value, which is
    -- a list of names (here represented as [String])
    let Just names = fromVariant (head (methodReturnBody reply))

    mapM_ putStrLn (sort names)


doGetSecrets :: (String -> String -> IO (String, String)) -> ConnectionHash -> ObjectPath -> String -> [String] -> Word32 -> IO ConnectionHash
doGetSecrets getSecrets c cPath settingName hints flags = do
    print "Someone's asking me for secrets!!"
    print $ "Requesting " ++ settingName
    let Just connection = M.lookup "connection" c
        Just uuid       = M.lookup "uuid" connection >>= fromVariant
    (key, secret) <- getSecrets uuid settingName
    return $ M.singleton settingName (M.singleton key (toVariant secret))

keyRingGetConnectionSecret kr uuid settingName = do
    items <- sync_ $ findItems ItemGenericSecret [snAttr, uuidAttr]
    case items of
        []     -> do
            sync_ $ createItem kr ItemGenericSecret ("Secret Key for " ++ settingName) createAttrs fakeSecret True
            return ("psk", fakeSecret)
        (i:is) -> do
            unless (null is) (print "Unexpected duplicate matching keyring entries. First will be used.")
            return ("psk", foundItemSecret i)
  where
    fakeSecret = "imalwaysthewrongsecretchangeme"
    snAttr   = TextAttribute "setting-name" settingName
    uuidAttr = TextAttribute "connection-uuid" uuid
    createAttrs = [TextAttribute "xdg:schema" "org.freedesktop.NetworkManager.Connection", TextAttribute "setting-key" "psk", uuidAttr, snAttr]

-- | Useful function for listing the contents of a keyring
listKeyringItems kr = do
    sync_ $ unlockKeyring kr Nothing
    itemIds <- sort <$> sync_ (listItemIDs kr)
    mapM_ (printItem kr) itemIds

printItem kr itemId = do
    item <- sync_ $ getItem kr True itemId
    attrs <- sync_ $ getItemAttributes kr itemId
    print $ show item ++ " " ++ show attrs
