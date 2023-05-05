{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Update_simplexmq () where

import Control.Applicative
import Control.Concurrent.STM.TBQueue
import Control.Concurrent.STM.TQueue
import Control.Concurrent.STM.TVar
import Control.Monad
import Control.Monad.STM
import Data.Functor
import Lowarn
import Lowarn.TH
import Lowarn.Transformer
import qualified NextVersion.EntryPoint as NextVersion
import qualified NextVersion.Simplex.Messaging.Crypto as NextVersion
import qualified NextVersion.Simplex.Messaging.Protocol as NextVersion
import qualified NextVersion.Simplex.Messaging.Server.Env.STM as NextVersion
import qualified NextVersion.Simplex.Messaging.Server.StoreLog as NextVersion
import qualified NextVersion.Simplex.Messaging.Transport as NextVersion
import qualified NextVersion.Simplex.Messaging.Transport.WebSockets as NextVersion
import qualified PreviousVersion.Simplex.Messaging.Crypto as PreviousVersion
import qualified PreviousVersion.Simplex.Messaging.Protocol as PreviousVersion
import qualified PreviousVersion.Simplex.Messaging.Server.Env.STM as PreviousVersion
import qualified PreviousVersion.Simplex.Messaging.Transport as PreviousVersion
import qualified PreviousVersion.Simplex.Messaging.Transport.WebSockets as PreviousVersion
import Type.Reflection

instance (Transformable a b) => Transformable (TVar a) (TVar b) where
  transform :: TVar a -> IO (Maybe (TVar b))
  transform =
    readTVarIO >=> transform >=> \case
      Nothing -> return Nothing
      Just x -> Just <$> newTVarIO x

instance (Transformable [a] [b]) => Transformable (TQueue a) (TQueue b) where
  transform :: TQueue a -> IO (Maybe (TQueue b))
  transform =
    (atomically . flushTQueue) >=> transform >=> \case
      Nothing -> return Nothing
      Just (xs :: [b]) -> atomically $ do
        queue <- newTQueue
        forM_ xs (writeTQueue queue)
        return $ Just queue

instance (Transformable [a] [b]) => Transformable (TBQueue a) (TBQueue b) where
  transform :: TBQueue a -> IO (Maybe (TBQueue b))
  transform tbQueue =
    atomically (flushTBQueue tbQueue) >>= transform >>= \case
      Nothing -> return Nothing
      Just (xs :: [b]) -> atomically $ do
        queue <- newTBQueue $ sizeTBQueue tbQueue
        forM_ xs (writeTBQueue queue)
        return $ Just queue

instance Transformable a (Maybe (NextVersion.StoreLog b)) where
  transform :: a -> IO (Maybe (Maybe (NextVersion.StoreLog b)))
  transform _ = return $ Just Nothing

instance
  Transformable
    (PreviousVersion.PublicKey 'PreviousVersion.Ed25519)
    (NextVersion.PublicKey 'NextVersion.Ed25519)
  where
  transform ::
    PreviousVersion.PublicKey 'PreviousVersion.Ed25519 ->
    IO (Maybe (NextVersion.PublicKey 'NextVersion.Ed25519))
  transform (PreviousVersion.PublicKeyEd25519 k) =
    return $ Just $ NextVersion.PublicKeyEd25519 k

instance
  Transformable
    (PreviousVersion.PublicKey 'PreviousVersion.Ed448)
    (NextVersion.PublicKey 'NextVersion.Ed448)
  where
  transform ::
    PreviousVersion.PublicKey 'PreviousVersion.Ed448 ->
    IO (Maybe (NextVersion.PublicKey 'NextVersion.Ed448))
  transform (PreviousVersion.PublicKeyEd448 k) =
    return $ Just $ NextVersion.PublicKeyEd448 k

instance
  Transformable
    (PreviousVersion.PublicKey 'PreviousVersion.X25519)
    (NextVersion.PublicKey 'NextVersion.X25519)
  where
  transform ::
    PreviousVersion.PublicKey 'PreviousVersion.X25519 ->
    IO (Maybe (NextVersion.PublicKey 'NextVersion.X25519))
  transform (PreviousVersion.PublicKeyX25519 k) =
    return $ Just $ NextVersion.PublicKeyX25519 k

instance
  Transformable
    (PreviousVersion.PublicKey 'PreviousVersion.X448)
    (NextVersion.PublicKey 'NextVersion.X448)
  where
  transform ::
    PreviousVersion.PublicKey 'PreviousVersion.X448 ->
    IO (Maybe (NextVersion.PublicKey 'NextVersion.X448))
  transform (PreviousVersion.PublicKeyX448 k) =
    return $ Just $ NextVersion.PublicKeyX448 k

instance
  Transformable
    (PreviousVersion.DhSecret 'PreviousVersion.X25519)
    (NextVersion.DhSecret 'NextVersion.X25519)
  where
  transform ::
    PreviousVersion.DhSecret 'PreviousVersion.X25519 ->
    IO (Maybe (NextVersion.DhSecret 'NextVersion.X25519))
  transform (PreviousVersion.DhSecretX25519 k) =
    return $ Just $ NextVersion.DhSecretX25519 k

instance
  Transformable
    (PreviousVersion.DhSecret 'PreviousVersion.X448)
    (NextVersion.DhSecret 'NextVersion.X448)
  where
  transform ::
    PreviousVersion.DhSecret 'PreviousVersion.X448 ->
    IO (Maybe (NextVersion.DhSecret 'NextVersion.X448))
  transform (PreviousVersion.DhSecretX448 k) =
    return $ Just $ NextVersion.DhSecretX448 k

instance Transformable PreviousVersion.Cmd NextVersion.Cmd where
  transform :: PreviousVersion.Cmd -> IO (Maybe NextVersion.Cmd)
  transform (PreviousVersion.Cmd sParty command) = case sParty of
    PreviousVersion.SRecipient -> do
      command' <- transform command
      return $ NextVersion.Cmd NextVersion.SRecipient <$> command'
    PreviousVersion.SSender -> do
      command' <- transform command
      return $ NextVersion.Cmd NextVersion.SSender <$> command'
    PreviousVersion.SNotifier -> do
      command' <- transform command
      return $ NextVersion.Cmd NextVersion.SNotifier <$> command'

instance
  Transformable
    (PreviousVersion.Command 'PreviousVersion.Recipient)
    (NextVersion.Command 'NextVersion.Recipient)
  where
  transform ::
    PreviousVersion.Command 'PreviousVersion.Recipient ->
    IO (Maybe (NextVersion.Command 'NextVersion.Recipient))
  transform (PreviousVersion.NEW k1 k2) = do
    k1' <- transform k1
    k2' <- transform k2
    return $ NextVersion.NEW <$> k1' <*> k2'
  transform PreviousVersion.SUB = return $ Just NextVersion.SUB
  transform (PreviousVersion.KEY k) = do
    k' <- transform k
    return $ NextVersion.KEY <$> k'
  transform (PreviousVersion.NKEY k1 k2) = do
    k1' <- transform k1
    k2' <- transform k2
    return $ NextVersion.NKEY <$> k1' <*> k2'
  transform PreviousVersion.NDEL = return $ Just NextVersion.NDEL
  transform PreviousVersion.GET = return $ Just NextVersion.GET
  transform (PreviousVersion.ACK m) = do
    m' <- transform m
    return $ NextVersion.ACK <$> m'
  transform PreviousVersion.OFF = return $ Just NextVersion.OFF
  transform PreviousVersion.DEL = return $ Just NextVersion.DEL

instance
  Transformable
    (PreviousVersion.Command 'PreviousVersion.Sender)
    (NextVersion.Command 'NextVersion.Sender)
  where
  transform ::
    PreviousVersion.Command 'PreviousVersion.Sender ->
    IO (Maybe (NextVersion.Command 'NextVersion.Sender))
  transform (PreviousVersion.SEND m1 m2) = do
    m1' <- transform m1
    m2' <- transform m2
    return $ NextVersion.SEND <$> m1' <*> m2'
  transform PreviousVersion.PING = return $ Just NextVersion.PING

instance
  Transformable
    (PreviousVersion.Command 'PreviousVersion.Notifier)
    (NextVersion.Command 'NextVersion.Notifier)
  where
  transform ::
    PreviousVersion.Command 'PreviousVersion.Notifier ->
    IO (Maybe (NextVersion.Command 'NextVersion.Notifier))
  transform PreviousVersion.NSUB = return $ Just NextVersion.NSUB

instance
  Transformable
    PreviousVersion.APublicVerifyKey
    NextVersion.APublicVerifyKey
  where
  transform ::
    PreviousVersion.APublicVerifyKey ->
    IO (Maybe NextVersion.APublicVerifyKey)
  transform (PreviousVersion.APublicVerifyKey sAlgorithm signatureAlgorithm) =
    case sAlgorithm of
      PreviousVersion.SEd25519 -> do
        signatureAlgorithm' <- transform signatureAlgorithm
        return $
          NextVersion.APublicVerifyKey NextVersion.SEd25519
            <$> signatureAlgorithm'
      PreviousVersion.SEd448 -> do
        signatureAlgorithm' <- transform signatureAlgorithm
        return $
          NextVersion.APublicVerifyKey NextVersion.SEd448
            <$> signatureAlgorithm'

instance Transformable PreviousVersion.ATransport NextVersion.ATransport where
  transform :: PreviousVersion.ATransport -> IO (Maybe NextVersion.ATransport)
  transform (PreviousVersion.ATransport (PreviousVersion.TProxy tRep)) =
    return $
      asum
        [ tRep `eqTypeRep` typeRep @PreviousVersion.TLS
            $> NextVersion.ATransport
              (NextVersion.TProxy $ typeRep @NextVersion.TLS),
          tRep `eqTypeRep` typeRep @PreviousVersion.WS
            $> NextVersion.ATransport
              (NextVersion.TProxy $ typeRep @NextVersion.WS)
        ]

instance DatatypeNameAlias "QueueStatus" "ServerQueueStatus"

update :: Update PreviousVersion.Env NextVersion.Env
update = Update transformer NextVersion.entryPoint

updateExportDeclarations 'update
