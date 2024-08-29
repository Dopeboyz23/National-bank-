https://bitcoincore.org/bin/bitcoin-core-27.1/SHA256SUMS?utm_source=tokenpocketconstructed using ⍴ (reshape):
4 3 ⍴ ⍳5                 ⍝ 0 1 2
                         ⍝ 3 4 0
                         ⍝ 1 2 3
                         ⍝ 4 0 1

⍝ Single-argument ⍴ gives you the dimensions back:
⍴ 4 3 ⍴ ⍳5               ⍝ 4 3

⍝ Values can be stored using ←. Let's calculate the mean
⍝ value of a vector of numbers:
A ← 10 60 55 23

⍝ Sum of elements of A (/ is reduce):
+/A                      ⍝ 148

⍝ Length of A:
⍴A                       ⍝ 4

⍝ Mean:
(+/A) ÷ (⍴A)             ⍝ 37

⍝ We can define this as a function using {} and ⍵:
mean ← {(+/⍵)÷⍴⍵}
mean A                   ⍝ 37
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`Badge component applestore renders correctly 1`] = `
<a
  class="sc-htpNat mBQkt"
  color="blue600"
  href="https://itunes.apple.com/us/app/blockchain-bitcoin-wallet/id493253309"
  target="_blank"
>
  <img
    class="sc-bwzfXH crzioW"
    color="auto"
    height="48px"
    src="[object Object]"
    srcset=""
    width="auto"
  />
</a>
`;

exports[`Badge component googleplay renders correctly 1`] = `
<a
  class="sc-htpNat mBQkt"
  color="blue600"
  href="https://play.google.com/store/apps/details?id=piuk.blockchain.android"
  target="_blank"
>
  <img
    class="sc-bwzfXH crzioW"
    color="auto"
    height="48px"
    src="[object Object]"
    srcset=""
    width="auto"
  />
</a>
`;{
  "label": "BTC DeFi Wallet",
  "archived": false,
  "default_derivation": "bech32",
  "derivations": [
    {
      "type": "legacy",
      "purpose": 44,
      "xpriv": "xprv9yL1ousLjQQzGNBAYykaT8J3U626NV6zbLYkRv8rvUDpY4f1RnrvAXQneGXC9UNuNvGXX4j6oHBK5KiV2hKevRxY5ntis212oxjEL11ysuG",
      "xpub": "xpub6CKNDRQEZmyHUrFdf1HapGEn27ramwpqxZUMEJYUUokoQrz9yLBAiKjGVWDuiCT39udj1r3whqQN89Tar5KrojH8oqSy7ytzJKW8gwmhwD3",
      "address_labels": [
        {
          "index": 0,
          "label": "labeled_address"
        }
      ],
      "cache": {
        "receiveAccount": "xpub6F41z8MqNcJMvKQgAd5QE2QYo32cocYigWp1D8726ykMmaMqvtqLkvuL1NqGuUJvU3aWyJaV2J4V6sD7Pv59J3tYGZdYRSx8gU7EG8ZuPSY",
        "changeAccount": "xpub6F41z8MqNcJMwmeUExdCv7UXvYBEgQB29SWq9jyxuZ7WefmSTWcwXB6NRAJkGCkB3L1Eu4ttzWnPVKZ6REissrQ4i6p8gTi9j5YwDLxmZ8p"
      }
    }
  ]
}{
  "guid": "50dae286-e42e-4d67-8419-d5dcc563746c",
  "sharedKey": "8a260b2b-5257-4357-ac56-7a7efca323ea",
  "double_encryption": false,
  "metadataHDNode": "xprv9tygGQP8be7uzNm5Czuy41juTK9pUKnWyZtDxgbmSEcCYa9VdvvtSknEyiKitqqm2TMv14NjXPQ68XLwSdH6Scc5GwXoZ31yRZZysxhVGU7",
  "options": {
    "pbkdf2_iterations": 5000,
    "fee_per_kb": 10000,
    "html5_notifications": false,
    "logout_time": 600000
  },
  "address_book": [],
  "tx_notes": {},
  "tx_names": [],
  "keys": [
    {
      "addr": "19XmKRY66VnUn5irHAafyoTfiwFuGLUxKF",
      "priv": "38W3vsxt246Lhawvz81y2HQVnsJrBUX87jSTUUnixPsE",
      "tag": 0,
      "label": "",
      "created_time": 1492721419269,
      "created_device_name": "javascript_web",
      "created_device_version": "3.0"
    },
    {
      "addr": "14mQxLtEagsS8gYsdWJbzthFFuPDqDgtxQ",
      "priv": "BpD2ZuJjZ8PJPpDX6ZmsKFsXHkL7XV3dt385zghMfF6C",
      "tag": 0,
      "label": "labeled_imported",
      "created_time": 1492721432222,
      "created_device_name": "javascript_web",
      "created_device_version": "3.0"
    },
    {
      "addr": "1JD73aGSdeqKUjJ4ntP4eCyUiuZ3ogJE1u",
      "priv": null,
      "tag": 0,
      "label": "",
      "created_time": 1492721461228,
      "created_device_name": "javascript_web",
      "created_device_version": "3.0"
    }
  ],
  "hd_wallets": [
    {
      "seed_hex": "6a4d9524d413fdf69ca1b5664d1d6db0",
      "passphrase": "",
      "mnemonic_verified": false,
      "default_account_idx": 0,
      "accounts": [
        {
          "label": "BTC DeFi Wallet",
          "archived": false,
          "xpriv": "xprv9yL1ousLjQQzGNBAYykaT8J3U626NV6zbLYkRv8rvUDpY4f1RnrvAXQneGXC9UNuNvGXX4j6oHBK5KiV2hKevRxY5ntis212oxjEL11ysuG",
          "xpub": "xpub6CKNDRQEZmyHUrFdf1HapGEn27ramwpqxZUMEJYUUokoQrz9yLBAiKjGVWDuiCT39udj1r3whqQN89Tar5KrojH8oqSy7ytzJKW8gwmhwD3",
          "address_labels": [
            {
              "index": 0,
              "label": "labeled_address"
            }
          ],
          "cache": {
            "receiveAccount": "xpub6F41z8MqNcJMvKQgAd5QE2QYo32cocYigWp1D8726ykMmaMqvtqLkvuL1NqGuUJvU3aWyJaV2J4V6sD7Pv59J3tYGZdYRSx8gU7EG8ZuPSY",
            "changeAccount": "xpub6F41z8MqNcJMwmeUExdCv7UXvYBEgQB29SWq9jyxuZ7WefmSTWcwXB6NRAJkGCkB3L1Eu4ttzWnPVKZ6REissrQ4i6p8gTi9j5YwDLxmZ8p"
          }
        }
      ]
    }
  ]import { is, map, pipe } from 'ramda'
import { view } from 'ramda-lens'

import * as HDWallet from './HDWallet'
import List from './List'

export class HDWalletList extends List {}

export const isHDWalletList = is(HDWalletList)

// we never add multiple hdwallets
// select always by default hdwallet 0
export const hdwallet = HDWalletList.define(0)

export const selectHDWallet = view(hdwallet)

export const toJS = pipe(HDWalletList.guard, (wList) => {
  return map(HDWallet.toJS, wList).toArray()
})

export const fromJS = (wallets) => {
  if (is(HDWalletList, wallets)) {
    return wallets
  }
  const ws = wallets || []
  return new HDWalletList(map(HDWallet.fromJS, ws))
}

export const createNew = (
  guid,
  password,
  sharedKey,
  mnemonic,
  firstAccountName = 'DeFi Wallet',
  nAccounts = 1
) => fromJS([HDWallet.js(firstAccountName, mnemonic, undefined, nAccounts, undefined)])

export const reviver = (jsObject) => {
  return new HDWalletList(jsObject)
}import BIP39 from 'bip39-light'
import * as Bitcoin from 'bitcoinjs-lib'
import Base58 from 'bs58'
import Either from 'data.either'
import Maybe from 'data.maybe'
import Task from 'data.task'
import memoize from 'fast-memoize'
import { __, compose, concat, curry, flip, is, isNil, map, pipe, split } from 'ramda'
import { over, set, traversed, traverseOf, view } from 'ramda-lens'

import { keyPairToAddress } from '../utils/btc'
import * as crypto from '../walletCrypto'
import * as Address from './Address'
import * as AddressBook from './AddressBook'
import * as AddressLabelMap from './AddressLabelMap'
import * as AddressMap from './AddressMap'
import * as Derivation from './Derivation'
import * as DerivationList from './DerivationList'
import * as HDAccount from './HDAccount'
import * as HDAccountList from './HDAccountList'
import * as HDWallet from './HDWallet'
import * as HDWalletList from './HDWalletList'
import * as Options from './Options'
import * as TXNames from './TXNames'
import * as TXNotes from './TXNotes'
import Type from './Type'
import { shift, shiftIProp } from './util'

/* Wallet :: {
  guid :: String
  sharedKey :: String
  double_encryption :: Bool
  metadataHDNode :: String
  options :: Options
  address_book :: [{ [addr]: String }]
  tx_notes :: [{ txhash: String }]
  tx_names :: []
  addresses :: {Address}
  hd_wallets :: [HDWallet]
} */

export class Wallet extends Type {}

export const isWallet = is(Wallet)

export const guid = Wallet.define('guid')
export const sharedKey = Wallet.define('sharedKey')
export const doubleEncryption = Wallet.define('double_encryption')
export const metadataHDNode = Wallet.define('metadataHDNode')
export const options = Wallet.define('options')
export const addresses = Wallet.define('addresses')
export const dpasswordhash = Wallet.define('dpasswordhash')
export const hdWallets = Wallet.define('hd_wallets')
export const txNotes = Wallet.define('tx_notes')
export const txNames = Wallet.define('tx_names')
export const addressBook = Wallet.define('address_book')

export const hdwallet = compose(hdWallets, HDWalletList.hdwallet)
export const accounts = compose(hdwallet, HDWallet.accounts)

export const selectGuid = view(guid)
export const selectSharedKey = view(sharedKey)
export const selectOptions = view(options)
export const selectmetadataHDNode = view(metadataHDNode)
export const selectTxNotes = view(txNotes)
export const selectTxNames = view(txNames)
export const selectAddressBook = view(addressBook)
export const selectIterations = compose(Options.selectPbkdf2Iterations, selectOptions)

export const selectHdWallets = view(hdWallets)
export const selectAddresses = compose(AddressMap.selectSpendable, view(addresses))
export const isDoubleEncrypted = compose(Boolean, view(doubleEncryption))

export const selectAddrContext = compose(
  AddressMap.selectContext,
  AddressMap.selectActive,
  selectAddresses
)
export const selectXpubsContextGrouped = compose(
  HDWallet.selectContextGrouped,
  HDWalletList.selectHDWallet,
  selectHdWallets
)
export const selectXpubsContext = compose(
  HDWallet.selectContext,
  HDWalletList.selectHDWallet,
  selectHdWallets
)
export const selectSpendableAddrContext = compose(
  AddressMap.selectContext,
  AddressMap.selectSpendable,
  selectAddresses
)
export const selectContextGrouped = (w) => ({
  addresses: selectAddrContext(w).toJS(),
  ...selectXpubsContextGrouped(w)
})
export const selectContext = (w) => selectAddrContext(w).concat(selectXpubsContext(w))
export const selectHDAccounts = (w) => selectHdWallets(w).flatMap(HDWallet.selectAccounts)
export const selectSpendableContext = (w) =>
  selectSpendableAddrContext(w).concat(selectXpubsContext(w))

const shiftWallet = compose(shiftIProp('keys', 'addresses'), shift)

export const fromJS = (x) => {
  if (is(Wallet, x)) {
    return x
  }
  const walletCons = compose(
    over(hdWallets, HDWalletList.fromJS),
    over(addresses, AddressMap.fromJS),
    over(options, Options.fromJS),
    over(txNames, TXNames.fromJS),
    over(txNotes, TXNotes.fromJS),
    over(addressBook, AddressBook.fromJS),
    (w) => shiftWallet(w).forward()
  )
  return walletCons(new Wallet(x))
}

export const toJS = pipe(Wallet.guard, (wallet) => {
  const walletDecons = compose(
    (w) => shiftWallet(w).back(),
    over(options, Options.toJS),
    over(txNotes, TXNotes.toJS),
    over(txNames, TXNames.toJS),
    over(hdWallets, HDWalletList.toJS),
    over(addresses, AddressMap.toJS),
    over(addressBook, AddressBook.toJS)
  )
  return walletDecons(wallet).toJS()
})

export const reviver = (jsObject) => {
  return new Wallet(jsObject)
}

export const spendableActiveAddresses = (wallet) => {
  const isSpendableActive = (a) => !Address.isWatchOnly(a) && !Address.isArchived(a)
  return selectAddresses(wallet)
    .filter(isSpendableActive)
    .map((a) => a.addr)
}

// fromEncryptedPayload :: String -> String -> Task Error Wallet
export const fromEncryptedPayload = curry((password, payload) => {
  return Task.of(payload).chain(crypto.decryptWallet(password)).map(fromJS)
})

// toEncryptedPayload :: String -> Wallet -> Task Error String
export const toEncryptedPayload = curry((password, pbkdf2Iterations, version, wallet) => {
  Wallet.guard(wallet)
  return compose(
    crypto.encryptWallet(__, password, pbkdf2Iterations, version),
    JSON.stringify,
    toJS
  )(wallet)
})

// isValidSecondPwd :: String -> Wallet -> Bool
export const isValidSecondPwd = curry((password, wallet) => {
  if (isDoubleEncrypted(wallet)) {
    if (!is(String, password)) {
      return false
    }
    // 5000 is fallback for v1 wallets that are missing
    // Pbkdf2 Iterations in the inner wrapper of JSON
    const iter = selectIterations(wallet) || 5000
    const sk = view(sharedKey, wallet)
    const storedHash = view(dpasswordhash, wallet)
    const computedHash = crypto.hashNTimes(iter, concat(sk, password)).toString('hex')
    return storedHash === computedHash
  }
  return true
})

// getAddress :: String -> Wallet -> Maybe Address
export const getAddress = curry((addr, wallet) => {
  const address = AddressMap.selectAddress(addr, wallet.addresses)
  return Maybe.fromNullable(address)
})

// getAccount :: Integer -> Wallet -> Maybe HDAccount
export const getAccount = curry((index, wallet) =>
  compose(
    Maybe.fromNullable,
    selectHdWallets
  )(wallet)
    .chain(compose(Maybe.fromNullable, HDWalletList.selectHDWallet))
    .chain(compose(Maybe.fromNullable, HDWallet.selectAccount(index)))
)

// applyCipher :: Wallet -> String -> Cipher -> a -> Task Error a
const applyCipher = curry((wallet, password, f, value) => {
  const it = selectIterations(wallet)
  const sk = view(sharedKey, wallet)
  switch (true) {
    case !isDoubleEncrypted(wallet):
      return Task.of(value)
    case isValidSecondPwd(password, wallet):
      return f(it, sk, password, value)
    default:
      return Task.rejected(new Error('INVALID_SECOND_PASSWORD'))
  }
})

// importLegacyAddress :: Wallet -> String -> Number -> String? -> { Network, Api } -> Task Error Wallet
export const importLegacyAddress = curry(
  (wallet, key, createdTime, password, bipPass, label, { api, network }) => {
    const checkIfExists = (address) =>
      getAddress(address.addr, wallet)
        .map((existing) =>
          Address.isWatchOnly(existing) && !Address.isWatchOnly(address)
            ? Task.of(existing)
            : Task.rejected(new Error('present_in_wallet'))
        )
        .map((aE) => aE.map(set(Address.priv, address.priv)))
        .getOrElse(Task.of(address))

    const appendAddress = (address) =>
      over(addresses, (as) => as.set(address.addr, address), wallet)

    return Address.fromString(key, createdTime, label, bipPass, {
      api,
      network
    })
      .chain(checkIfExists)
      .chain(applyCipher(wallet, password, Address.encrypt))
      .map(appendAddress)
  }
)

// upgradeToV4 :: String -> String -> Network -> Wallet -> Task Error Wallet
export const upgradeToV4 = curry((seedHex, password, network, wallet) => {
  const encryptDerivation = applyCipher(wallet, password, Derivation.encrypt)
  const upgradeAccount = (account) => {
    const migratedAccount = HDAccount.fromJS(HDAccount.toJS(account), account.index)
    const addDerivationToAccount = (derivation) =>
      over(HDAccount.derivations, (derivations) => derivations.push(derivation), migratedAccount)
    const derivation = HDWallet.generateDerivation(
      HDAccount.DEFAULT_DERIVATION_TYPE,
      HDAccount.DEFAULT_DERIVATION_PURPOSE,
      migratedAccount.index,
      network,
      seedHex
    )

    return encryptDerivation(derivation).map(addDerivationToAccount)
  }

  const traverseAllAccounts = compose(hdwallet, HDWallet.accounts, traversed)

  return traverseOf(traverseAllAccounts, Task.of, upgradeAccount, wallet)
})

// newHDWallet :: String -> String? -> Wallet -> Task Error Wallet
export const newHDWallet = curry((mnemonic, password, wallet) => {
  const hdWallet = HDWallet.createNew(mnemonic)
  const appendHdWallet = curry((w, hd) => over(hdWallets, (list) => list.push(hd), w))
  return applyCipher(wallet, password, HDWallet.encrypt, hdWallet).map(appendHdWallet(wallet))
})

// newHDAccount :: String -> String? -> Wallet -> Task Error Wallet
export const newHDAccount = curry((label, password, network, payloadV, wallet) => {
  const hdWallet = HDWalletList.selectHDWallet(selectHdWallets(wallet))
  const index = hdWallet.accounts.size
  const appendAccount = curry((w, account) => {
    const accountsLens = compose(hdWallets, HDWalletList.hdwallet, HDWallet.accounts)
    const accountWithIndex = set(HDAccount.index, index, account)
    return over(accountsLens, (accounts) => accounts.push(accountWithIndex), w)
  })
  return applyCipher(wallet, password, flip(crypto.decryptSecPass), hdWallet.seedHex)
    .map(HDWallet.generateAccount(index, label, network, payloadV))
    .chain(applyCipher(wallet, password, HDAccount.encrypt))
    .map(appendAccount(wallet))
})

// upgradeToV3 :: String -> String -> String? -> Task Error Wallet
export const upgradeToV3 = curry((mnemonic, firstLabel, password, network, wallet) => {
  return newHDWallet(mnemonic, password, wallet).chain(
    newHDAccount(firstLabel, password, network, 3)
  )
})

// setLegacyAddressLabel :: String -> String -> Wallet -> Wallet
export const setLegacyAddressLabel = curry((address, label, wallet) => {
  const addressLens = compose(addresses, AddressMap.address(address))
  const eitherW = Either.try(over(addressLens, Address.setLabel(label)))(wallet)
  return eitherW.getOrElse(wallet)
})

// getPrivateKeyForAddress :: Wallet -> String? -> String -> Task Error String
export const getPrivateKeyForAddress = curry((wallet, password, addr) => {
  const address = AddressMap.selectAddress(addr, selectAddresses(wallet))
  return applyCipher(wallet, password, Address.decrypt, address).map((a) => a.priv)
})

// setLegacyAddressLabel :: String -> Bool -> Wallet -> Wallet
export const setAddressArchived = curry((address, archived, wallet) => {
  const addressLens = compose(addresses, AddressMap.address(address))
  return over(addressLens, Address.setArchived(archived), wallet)
})

// deleteLegacyAddress :: String -> Wallet -> Wallet
export const deleteLegacyAddress = curry((address, wallet) => {
  return over(addresses, AddressMap.deleteAddress(address), wallet)
})

// deleteHdAddressLabel :: Number -> Number -> String -> Wallet -> Wallet
export const deleteHdAddressLabel = curry((accountIdx, addressIdx, derivationType, wallet) => {
  const lens = compose(
    hdWallets,
    HDWalletList.hdwallet,
    HDWallet.accounts,
    HDAccountList.account(accountIdx),
    HDAccount.derivations,
    DerivationList.derivationOfType(derivationType),
    Derivation.addressLabels
  )
  const eitherW = Either.try(over(lens, AddressLabelMap.deleteLabel(addressIdx)))(wallet)
  return eitherW.getOrElse(wallet)
})

// setHdAddressLabel :: Number -> Number -> String -> Wallet -> Wallet
export const setHdAddressLabel = curry((accountIdx, addressIdx, derivationType, label, wallet) => {
  const lens = compose(
    hdWallets,
    HDWalletList.hdwallet,
    HDWallet.accounts,
    HDAccountList.account(accountIdx),
    HDAccount.derivations,
    DerivationList.derivationOfType(derivationType),
    Derivation.addressLabels
  )
  const eitherW = Either.try(over(lens, AddressLabelMap.setLabel(addressIdx, label)))(wallet)
  return eitherW.getOrElse(wallet)
})

// setAccountLabel :: Number -> String -> Wallet -> Wallet
export const setAccountLabel = curry((accountIdx, label, wallet) => {
  const lens = compose(accounts, HDAccountList.account(accountIdx), HDAccount.label)
  return set(lens, label, wallet)
})

// setAccountArchived :: Number -> Bool -> Wallet -> Wallet
export const setAccountArchived = curry((index, archived, wallet) => {
  const lens = compose(accounts, HDAccountList.account(index), HDAccount.archived)
  return set(lens, archived, wallet)
})

// setAccountDerivations :: Number -> Derivations -> Wallet -> Wallet
export const setAccountDerivations = curry((index, derivations, wallet) => {
  const lens = compose(accounts, HDAccountList.account(index), HDAccount.derivations)
  return set(lens, derivations, wallet)
})

// setDefaultDerivation :: Number -> derivationType -> Wallet -> Wallet
export const setDefaultDerivation = curry((index, derivationType, wallet) => {
  const lens = compose(accounts, HDAccountList.account(index), HDAccount.defaultDerivation)
  return set(lens, derivationType, wallet)
})

// setDefaultAccountIdx :: Number -> Wallet -> Wallet
export const setDefaultAccountIdx = curry((index, wallet) => {
  return set(compose(hdwallet, HDWallet.defaultAccountIdx), index, wallet)
})
export const setTxNote = curry((txHash, txNote, wallet) => {
  return set(compose(txNotes, TXNotes.note(txHash)), txNote, wallet)
})

// traversePrivValues :: Monad m => (a -> m a) -> (String -> m String) -> Wallet -> m Wallet
export const traverseKeyValues = curry((of, f, wallet) => {
  const trAddr = traverseOf(compose(addresses, traversed, Address.priv), of, f)
  const trSeed = traverseOf(compose(hdWallets, traversed, HDWallet.seedHex), of, f)
  const trXpriv = traverseOf(compose(hdWallets, traversed, HDWallet.secretsLens), of, f)
  return of(wallet).chain(trAddr).chain(trSeed).chain(trXpriv)
})

// encryptMonadic :: Monad m => (a -> m a) -> (String -> m String) -> String -> Wallet -> m Wallet
export const encryptMonadic = curry((of, cipher, password, wallet) => {
  if (isDoubleEncrypted(wallet)) {
    return of(wallet)
  }
  const iter = selectIterations(wallet)
  const enc = cipher(wallet.sharedKey, iter, password)
  const hash = crypto.hashNTimes(iter, concat(wallet.sharedKey, password)).toString('hex')
  const setFlag = over(doubleEncryption, () => true)
  const setHash = over(dpasswordhash, () => hash)
  return traverseKeyValues(of, enc, wallet).map(compose(setHash, setFlag))
})

// encrypt :: String -> Wallet -> Task Error Wallet
export const encrypt = encryptMonadic(Task.of, crypto.encryptSecPass)

// decryptMonadic :: Monad m => (a -> m a) -> (String -> m String) -> (String -> m Wallet) -> String -> Wallet -> m Wallet
export const decryptMonadic = curry((of, cipher, verify, password, wallet) => {
  if (isDoubleEncrypted(wallet)) {
    const iter = selectIterations(wallet)
    const dec = cipher(wallet.sharedKey, iter, password)

    const setFlag = over(doubleEncryption, () => false)
    const setHash = over(Wallet.lens, (x) => x.delete('dpasswordhash'))

    return verify(password, wallet).chain(traverseKeyValues(of, dec)).map(compose(setHash, setFlag))
  }
  return of(wallet)
})

// validateSecondPwd :: (a -> m a) -> (a -> m b) -> String -> Wallet
export const validateSecondPwd = curry((pass, fail, password, wallet) =>
  isValidSecondPwd(password, wallet) ? pass(wallet) : fail(new Error('INVALID_SECOND_PASSWORD'))
)

// decrypt :: String -> Wallet -> Task Error Wallet
export const decrypt = decryptMonadic(
  Task.of,
  crypto.decryptSecPass,
  validateSecondPwd(Task.of, Task.rejected)
)

const _derivePrivateKey = (network, xpriv, chain, index) =>
  Bitcoin.bip32.fromBase58(xpriv, network).derive(chain).derive(index)

export const derivePrivateKey = memoize(_derivePrivateKey)

export const getHDPrivateKeyWIF = curry((coin, secondPassword, network, wallet) => {
  const type = coin.type() === 'P2PKH' ? 'legacy' : 'bech32'
  const [accId, chain, index] = map(parseInt, split('/', coin.path))
  if (isNil(accId) || isNil(chain) || isNil(index)) {
    return Task.rejected('WRONG_PATH_KEY')
  }
  const xpriv = compose(
    HDAccount.selectXpriv(type),
    HDWallet.selectAccount(accId),
    HDWalletList.selectHDWallet,
    selectHdWallets
  )(wallet)
  if (isDoubleEncrypted(wallet)) {
    return validateSecondPwd(Task.of, Task.rejected)(secondPassword, wallet)
      .chain(() =>
        crypto.decryptSecPass(
          selectSharedKey(wallet),
          selectIterations(wallet),
          secondPassword,
          xpriv
        )
      )
      .map((xp) => {
        const node = derivePrivateKey(network, xp, chain, index)
        return Bitcoin.ECPair.fromPrivateKey(node.privateKey).toWIF()
      })
  }
  return Task.of(xpriv).map((xp) => {
    const node = derivePrivateKey(network, xp, chain, index)
    return Bitcoin.ECPair.fromPrivateKey(node.privateKey).toWIF()
  })
})

// TODO :: find a proper place for that
const fromBase58toKey = (string, address, network) => {
  const key = Bitcoin.ECPair.fromPrivateKey(Base58.decode(string))
  if (keyPairToAddress(key) === address) return key
  key.compressed = !key.compressed
  return key
}

export const getLegacyPrivateKey = curry((address, secondPassword, network, wallet) => {
  const priv = compose(
    Address.selectPriv,
    AddressMap.selectAddress(address),
    selectAddresses
  )(wallet)
  if (isDoubleEncrypted(wallet)) {
    return validateSecondPwd(Task.of, Task.rejected)(secondPassword, wallet)
      .chain(() =>
        crypto.decryptSecPass(
          selectSharedKey(wallet),
          selectIterations(wallet),
          secondPassword,
          priv
        )
      )
      .map((pk) => fromBase58toKey(pk, address, network))
  }
  return Task.of(priv).map((pk) => fromBase58toKey(pk, address, network))
})

export const getLegacyPrivateKeyWIF = curry((address, secondPassword, network, wallet) => {
  return getLegacyPrivateKey(address, secondPassword, network, wallet).map((ecpair) =>
    ecpair.toWIF()
  )
})

// getSeedHex :: String -> Wallet -> Task Error String
export const getSeedHex = curry((secondPassword, wallet) => {
  const seedHex = compose(
    HDWallet.selectSeedHex,
    HDWalletList.selectHDWallet,
    selectHdWallets
  )(wallet)
  if (isDoubleEncrypted(wallet)) {
    return validateSecondPwd(Task.of, Task.rejected)(secondPassword, wallet).chain(() =>
      crypto.decryptSecPass(
        selectSharedKey(wallet),
        selectIterations(wallet),
        secondPassword,
        seedHex
      )
    )
  }
  return Task.of(seedHex)
})

// getMnemonic :: String -> Wallet -> Task Error String
export const getMnemonic = curry((secondPassword, wallet) => {
  const eitherToTask = (e) => e.fold(Task.rejected, Task.of)
  const entropyToMnemonic = compose(eitherToTask, Either.try(BIP39.entropyToMnemonic))
  const seedHex = getSeedHex(secondPassword, wallet)
  return seedHex.chain(entropyToMnemonic)
})

export const js = (guid, sharedKey, label, mnemonic, nAccounts, network) => ({
  address_book: [],
  double_encryption: false,
  guid,
  hd_wallets: [HDWallet.js(label, mnemonic, nAccounts, network)],
  keys: [],
  options: Options.js(),
  sharedKey,
  tx_names: [],
  tx_notes: {}
})export type ImportedAddrType = {
  addr: string
  created_device_name: string
  created_device_version: string
  created_time: number
  info: {
    address: string
    final_balance: number
    n_tx: number
    total_received: number
    total_sent: number
  }
  label?: string
  priv: null | string
  tag: number
}import { ECPair } from 'bitcoinjs-lib'
import Base58 from 'bs58'
import Either from 'data.either'
import Task from 'data.task'
import { compose, curry, equals, is, isNil, not, pipe } from 'ramda'
import { set, traverseOf, view } from 'ramda-lens'

import * as utils from '../utils'
import * as crypto from '../walletCrypto'
import { parseBIP38toECPair } from '../walletCrypto/importExport'
import Type from './Type'
import { iToJS } from './util'

const eitherToTask = (e) => e.fold(Task.rejected, Task.of)
const wrapPromiseInTask = (fP) => new Task((reject, resolve) => fP().then(resolve, reject))

/* Address :: {
  priv :: String
  addr :: String
  label :: String
  tag :: Number
  created_time :: Number
  created_device_name :: String
  created_device_version :: String
} */

export class Address extends Type {}

export const isAddress = is(Address)

export const priv = Address.define('priv')
export const addr = Address.define('addr')
export const label = Address.define('label')
export const tag = Address.define('tag')
export const createdTime = Address.define('created_time')
export const createdDeviceName = Address.define('created_device_name')
export const createdDeviceVersion = Address.define('created_device_version')

export const selectPriv = view(priv)
export const selectAddr = view(addr)
export const selectLabel = view(label)
export const selectTag = view(tag)
export const selectCreatedTime = view(createdTime)
export const selectCreatedDeviceName = view(createdDeviceName)
export const selectCreatedDeviceVersion = view(createdDeviceVersion)

export const isArchived = compose(equals(2), view(tag))
export const isActive = compose(not, isArchived)
export const isWatchOnly = compose(isNil, view(priv))
export const isNotWatchOnly = compose(not, isWatchOnly)

export const fromJS = (x) => (is(Address, x) ? x : new Address(x))

export const toJS = pipe(Address.guard, iToJS)

export const reviver = (jsObject) => {
  return new Address(jsObject)
}

// setLabel :: String -> Address -> Address
export const setLabel = set(label)

// archive :: Address -> Address
export const archive = set(tag, 2)

// unArchive :: Address -> Address
export const unArchive = set(tag, 0)

export const setArchived = curry((archived, address) => set(tag, archived ? 2 : 0, address))

// encrypt :: Number -> String -> String -> Address -> Task Error Address
export const encrypt = curry((iterations, sharedKey, password, address) => {
  const cipher = crypto.encryptSecPass(sharedKey, iterations, password)
  return traverseOf(priv, Task.of, cipher, address)
})

// decrypt :: Number -> String -> String -> Address -> Task Error Address
export const decrypt = curry((iterations, sharedKey, password, address) => {
  const cipher = crypto.decryptSecPass(sharedKey, iterations, password)
  return traverseOf(priv, Task.of, cipher, address)
})

// importAddress :: String|ECPair -> String? -> Number -> Network -> Address
export const importAddress = (key, createdTime, label, network) => {
  const object = {
    addr: null,
    created_device_name: 'wallet-web',
    created_device_version: 'v4',
    created_time: createdTime,
    label,
    priv: null,
    tag: 0
  }

  switch (true) {
    case utils.btc.isValidBtcAddress(key, network):
      object.addr = key
      object.priv = null
      break
    case utils.btc.isKey(key):
      object.addr = utils.btc.keyPairToAddress(key)
      object.priv = Base58.encode(key.privateKey)
      break
    case utils.btc.isValidBtcPrivateKey(key, network):
      key = ECPair.fromWIF(key, network)
      object.addr = utils.btc.keyPairToAddress(key)
      object.priv = Base58.encode(key.privateKey)
      break
    default:
      throw new Error('unsupported_address_import_format')
  }

  return fromJS(object)
}

// fromString :: String -> Number -> String? -> String? -> { Network, API } -> Task Error Address
export const fromString = (keyOrAddr, createdTime, label, bipPass, { api, network }) => {
  if (utils.btc.isValidBtcAddress(keyOrAddr)) {
    return Task.of(importAddress(keyOrAddr, createdTime, label, network))
  }
  const format = utils.btc.detectPrivateKeyFormat(keyOrAddr)
  const okFormats = ['base58', 'base64', 'hex', 'mini', 'sipa', 'compsipa']
  if (format === 'bip38') {
    if (bipPass == null || bipPass === '') {
      return Task.rejected(new Error('needs_bip38'))
    }
    const tryParseBIP38toECPair = Either.try(parseBIP38toECPair)
    const keyE = tryParseBIP38toECPair(keyOrAddr, bipPass, network)
    return eitherToTask(keyE).map((key) => importAddress(key, createdTime, label, network))
  }
  if (format === 'mini' || format === 'base58') {
    let key
    try {
      key = utils.btc.privateKeyStringToKey(keyOrAddr, format)
    } catch (e) {
      return Task.rejected(e)
    }
    key.compressed = true
    const cad = utils.btc.keyPairToAddress(key)
    key.compressed = false
    const uad = utils.btc.keyPairToAddress(key)
    return wrapPromiseInTask(() => api.getBalances([cad, uad])).fold(
      () => {
        key.compressed = true
        return importAddress(key, createdTime, label, network)
      },
      (o) => {
        const compBalance = o[cad].final_balance
        const ucompBalance = o[uad].final_balance
        key.compressed = !(compBalance === 0 && ucompBalance > 0)
        return importAddress(key, createdTime, label, network)
      }
    )
  }
  if (okFormats.indexOf(format) > -1) {
    const key = utils.btc.privateKeyStringToKey(keyOrAddr, format)
    return Task.of(importAddress(key, createdTime, label, network))
  }
  return Task.rejected(new Error('unknown_key_format'))
}import { map } from 'ramda'

import * as Coin from './coin.js'
import * as cs from './index'

describe('Coin Selection', () => {
  describe('byte sizes', () => {
    const legacyInput = { type: () => 'P2PKH' }
    const legacyOutput = { type: () => 'P2PKH' }
    const segwitInput = { type: () => 'P2WPKH' }
    const segwitOutput = { type: () => 'P2WPKH' }

    describe('0x0 transactions', () => {
      it('should return the right transaction size (empty tx)', () => {
        // No witness => 10 vbytes
        expect(cs.transactionBytes([], [])).toEqual(10)
      })
    })

    describe('1x1 transactions', () => {
      it('should return the right transaction size (1 P2PKH, 1 P2PKH)', () => {
        // 10 + 148 + 34 = 192
        expect(cs.transactionBytes([legacyInput], [legacyOutput])).toEqual(192)
      })
      it('should return the right transaction size (1 P2PKH, 1 P2WPKH)', () => {
        // 10 + 148 + 31 = 189
        expect(cs.transactionBytes([legacyInput], [segwitOutput])).toEqual(189)
      })
      it('should return the right transaction size (1 P2WPKH, 1 P2PKH)', () => {
        // 10.75 + 67.75 + 34 = 112.5
        expect(cs.transactionBytes([segwitInput], [legacyOutput])).toEqual(112.5)
      })
      it('should return the right transaction size (1 P2WPKH, 1 P2WPKH)', () => {
        // 10.75 + 67.75 + 31 = 109.5
        expect(cs.transactionBytes([segwitInput], [segwitOutput])).toEqual(109.5)
      })
    })

    describe('1x2 transactions', () => {
      it('should return the right transaction size (1 P2PKH, 2 P2PKH)', () => {
        // 10 + 148 + 34*2 = 226
        expect(cs.transactionBytes([legacyInput], [legacyOutput, legacyOutput])).toEqual(226)
      })
      it('should return the right transaction size (1 P2PKH, 2 P2WPKH)', () => {
        // 10 + 148 + 31*2 = 220
        expect(cs.transactionBytes([legacyInput], [segwitOutput, segwitOutput])).toEqual(220)
      })
      it('should return the right transaction size (1 P2PKH, 1 P2PKH + 1 P2WPKH)', () => {
        // 10 + 148 + 31 + 34 = 223
        expect(cs.transactionBytes([legacyInput], [legacyOutput, segwitOutput])).toEqual(223)
      })
      it('should return the right transaction size (1 P2WPKH, 2 P2PKH)', () => {
        // 10.75 + 67.75 + 34*2 = 146.5
        expect(cs.transactionBytes([segwitInput], [legacyOutput, legacyOutput])).toEqual(146.5)
      })
      it('should return the right transaction size (1 P2WPKH, 2 P2WPKH)', () => {
        // 10.75 + 67.75 + 31*2 = 140.5
        expect(cs.transactionBytes([segwitInput], [segwitOutput, segwitOutput])).toEqual(140.5)
      })
      it('should return the right transaction size (1 P2WPKH, 1 P2PKH + 1 P2WPKH)', () => {
        // 10.75 + 67.75 + 31 + 34 = 143.5
        expect(cs.transactionBytes([segwitInput], [legacyOutput, segwitOutput])).toEqual(143.5)
      })
    })

    describe('2x1 transactions', () => {
      it('should return the right transaction size (2 P2PKH, 1 P2PKH)', () => {
        // 10 + 148*2 + 34 = 340
        expect(cs.transactionBytes([legacyInput, legacyInput], [legacyOutput])).toEqual(340)
      })
      it('should return the right transaction size (2 P2PKH, 1 P2WPKH)', () => {
        // 10 + 148*2 + 31 = 337
        expect(cs.transactionBytes([legacyInput, legacyInput], [segwitOutput])).toEqual(337)
      })
      it('should return the right transaction size (1 P2PKH + P2WPKH, 1 P2PKH)', () => {
        // 10.75 + 67.75 + 148 + 34 = 260.5
        expect(cs.transactionBytes([legacyInput, segwitInput], [legacyOutput])).toEqual(260.5)
      })
      it('should return the right transaction size (2 P2WPKH, 1 P2PKH)', () => {
        // 10.75 + 67.75*2 + 34 = 180.25
        expect(cs.transactionBytes([segwitInput, segwitInput], [legacyOutput])).toEqual(180.25)
      })
      it('should return the right transaction size (2 P2WPKH, 1 P2WPKH)', () => {
        // 10.75 + 67.75*2 + 31 = 177.25
        expect(cs.transactionBytes([segwitInput, segwitInput], [segwitOutput])).toEqual(177.25)
      })
      it('should return the right transaction size (1 P2PKH + 1 P2WPKH, 1 P2WPKH)', () => {
        // 10.75 + 67.75 + 148 + 31 = 257.5
        expect(cs.transactionBytes([legacyInput, segwitInput], [segwitOutput])).toEqual(257.5)
      })
    })

    describe('2x2 transactions', () => {
      it('should return the right transaction size (2 P2PKH, 2 P2PKH)', () => {
        // 10 + 148*2 + 34*2 = 374
        expect(
          cs.transactionBytes([legacyInput, legacyInput], [legacyOutput, legacyOutput])
        ).toEqual(374)
      })
      it('should return the right transaction size (2 P2PKH, 2 P2WPKH)', () => {
        // 10 + 148*2 + 31*2 = 368
        expect(
          cs.transactionBytes([legacyInput, legacyInput], [segwitOutput, segwitOutput])
        ).toEqual(368)
      })
      it('should return the right transaction size (1 P2PKH + 1 P2WPKH, 2 P2PKH)', () => {
        // 10.75 + 148 + 67.75 + 34*2 = 294.5
        expect(
          cs.transactionBytes([legacyInput, segwitInput], [legacyOutput, legacyOutput])
        ).toEqual(294.5)
      })
      it('should return the right transaction size (2 P2PKH, 1 P2PKH + 1 P2WPKH)', () => {
        // 10 + 148*2 + 31 + 34 = 371
        expect(
          cs.transactionBytes([legacyInput, legacyInput], [legacyOutput, segwitOutput])
        ).toEqual(371)
      })
      it('should return the right transaction size (1 P2PKH + 1 P2PWKH, 1 P2PKH + 1 P2WPKH)', () => {
        // 10.75 + 67.75 + 148 + 31 + 34 = 291.5
        expect(
          cs.transactionBytes([legacyInput, segwitInput], [legacyOutput, segwitOutput])
        ).toEqual(291.5)
      })
      it('should return the right transaction size (2 P2WPKH, 2 P2PKH)', () => {
        // 10.75 + 67.75*2 + 34*2 = 214.25
        expect(
          cs.transactionBytes([segwitInput, segwitInput], [legacyOutput, legacyOutput])
        ).toEqual(214.25)
      })
      it('should return the right transaction size (2 P2WPKH, 2 P2WPKH)', () => {
        // 10.75 + 67.75*2 + 31*2 = 208.25
        expect(
          cs.transactionBytes([segwitInput, segwitInput], [segwitOutput, segwitOutput])
        ).toEqual(208.25)
      })
      it('should return the right transaction size (2 P2WPKH, 1 P2PKH + 1 P2WPKH)', () => {
        // 10.75 + 67.75*2 + 31 + 34 = 211.25
        expect(
          cs.transactionBytes([segwitInput, segwitInput], [legacyOutput, segwitOutput])
        ).toEqual(211.25)
      })
      it('should return the right transaction size (1 P2PKH + 1 P2WPKH, 2 P2WPKH)', () => {
        // 10.75 + 67.75 + 148 + 31*2 = 288.5
        expect(
          cs.transactionBytes([legacyInput, segwitInput], [segwitOutput, segwitOutput])
        ).toEqual(288.5)
      })
    })
  })

  describe('effective Balances', () => {
    it('should return the right effective max balance with no value and empty valued outputs', () => {
      const inputs = map(Coin.fromJS, [{ value: 15000 }, { value: 10000 }, { value: 20000 }])
      const outputs = map(Coin.fromJS, [{ value: 0 }, { value: 0 }])

      // sum of inputs - transactionBytes * feePerByte
      expect(cs.effectiveBalance(0, inputs, outputs).value).toEqual(45000)
    })
    it('should return the right effective max balance with value and empty valued outputs', () => {
      const inputs = map(Coin.fromJS, [{ value: 15000 }, { value: 10000 }, { value: 20000 }])

      const outputs = map(Coin.fromJS, [{ value: 0 }, { value: 0 }])

      // sum of inputs - transactionBytes * feePerByte
      // 45000 - 55 * (10 + 3*148 + 2*34) = 45000 - ceil(28710) = 16290
      expect(cs.effectiveBalance(55, inputs, outputs).value).toEqual(16290)
    })
    it('should return the right effective max balance with value and empty valued outputs (segwit)', () => {
      const inputs = map(Coin.fromJS, [
        { address: 'bc1qxddx2wmn97swgznpkthv940ktg8ycxg0ygxxp9', value: 15000 },
        { address: 'bc1qxddx2wmn97swgznpkthv940ktg8ycxg0ygxxp9', value: 10000 },
        { value: 20000 }
      ])

      const outputs = map(Coin.fromJS, [{ value: 0 }, { value: 0 }])

      // sum of inputs - transactionBytes * feePerByte
      // 45000 - 55 * (10.75 + 2*67.75 + 148 + 2*34) = 45000 - ceil(19923.75) = 25076
      expect(cs.effectiveBalance(55, inputs, outputs).value).toEqual(25076)
    })
    it('should return the right effective max balance w/ no inputs or outputs', () => {
      expect(cs.effectiveBalance(55, [], []).value).toEqual(0)
    })
    it('should return the right effective max balance w/ no value, inputs or outputs', () => {
      expect(cs.effectiveBalance(0, [], []).value).toEqual(0)
    })
  })

  describe('findTarget', () => {
    it('should return the right selection with empty inputs and targets,', () => {
      const selection = cs.findTarget([], 0, [])
      expect(selection.fee).toEqual(0)
      expect(selection.inputs).toEqual([])
      expect(selection.outputs).toEqual([])
    })
    it('should return the right selection without feePerByte set', () => {
      const inputs = map(Coin.fromJS, [{ value: 1 }, { value: 2 }, { value: 3 }])
      const targets = map(Coin.fromJS, [{ value: 10000 }])
      const selection = cs.findTarget(targets, 0, inputs)
      expect(selection.fee).toEqual(0)
      expect(selection.inputs).toEqual([])
      expect(selection.outputs).toEqual(targets)
    })
    it('should return the right selection with feePerByte set', () => {
      const inputs = map(Coin.fromJS, [{ value: 1 }, { value: 20000 }, { value: 300000 }])
      const targets = map(Coin.fromJS, [{ value: 10000 }])
      const feePerByte = 55
      const selection = cs.findTarget(targets, feePerByte, inputs)

      // Overhead + 2 Inputs + 2 Outputs (target + change)
      const expectedFee = (10 + 2 * 148 + 2 * 34) * feePerByte // 20570
      // Inputs - Target - Expected Fee
      const expectedChange = 300000 + 20000 - 10000 - expectedFee
      expect(selection.fee).toEqual(expectedFee)
      expect(selection.inputs.map((x) => x.value)).toEqual([20000, 300000])
      expect(selection.outputs.map((x) => x.value)).toEqual([10000, expectedChange])
    })
  })

  describe('selectAll', () => {
    it('should return the right selection with inputs', () => {
      const inputs = map(Coin.fromJS, [
        { value: 1 },
        { value: 20000 },
        { value: 0 },
        { value: 0 },
        { value: 300000 }
      ])

      const selection = cs.selectAll(55, inputs)
      expect(selection.inputs.map((x) => x.value)).toEqual([20000, 300000])

      // overhead + inputs + outputs
      // 55 * (10 + 148 * 2 + 34 * 1) = 55 * 340 = 18700
      expect(selection.fee).toEqual(18700)

      // change = inputs - outputs - fee
      // 20000 + 300000 - 18700 = 301300
      expect(selection.outputs.map((x) => x.value)).toEqual([301300])
    })
    it('should return the right selection without inputs', () => {
      const inputs = map(Coin.fromJS, [])
      const selection = cs.selectAll(55, inputs)
      expect(selection.fee).toEqual(0)
      expect(selection.inputs.map((x) => x.value)).toEqual([])
      expect(selection.outputs.map((x) => x.value)).toEqual([0])
    })
  })

  describe('compare', () => {
    it('should return the right selection for descentDraw', () => {
      const inputs = map(Coin.fromJS, [
        { confirmations: 1, value: 1 },
        { confirmations: 1, value: 20000 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 300000 },
        { confirmations: 1, value: 50000 },
        { confirmations: 1, value: 30000 }
      ])
      const result = inputs.sort((a, b) => a.descentCompareWeighted(b))
      const expected = [300000, 50000, 30000, 20000, 1, 0, 0]
      expect(result.map((x) => x.value)).toEqual(expected)
    })
    it('should return the right selection with demoted coins for descentDraw', () => {
      const inputs = map(Coin.fromJS, [
        { confirmations: 1, value: 1 },
        { confirmations: 1, value: 20000 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 300000 },
        { confirmations: 0, value: 50000 },
        { confirmations: 1, value: 30000 }
      ]) //
      const result = inputs.sort((a, b) => a.descentCompareWeighted(b))
      const expected = [300000, 30000, 20000, 1, 0, 0, 50000]
      expect(result.map((x) => x.value)).toEqual(expected)
    })
    it('should return the right selection for ascentDraw', () => {
      const inputs = map(Coin.fromJS, [
        { confirmations: 1, value: 1 },
        { confirmations: 1, value: 20000 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 300000 },
        { confirmations: 1, value: 50000 },
        { confirmations: 1, value: 30000 }
      ])
      const result = inputs.sort((a, b) => a.ascentCompareWeighted(b))
      const expected = [0, 0, 1, 20000, 30000, 50000, 300000]
      expect(result.map((x) => x.value)).toEqual(expected)
    })
    it('should return the right selection with demoted coins for ascentDraw', () => {
      const inputs = map(Coin.fromJS, [
        { confirmations: 1, value: 1 },
        { confirmations: 1, value: 20000 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 300000 },
        { confirmations: 0, value: 50000 },
        { confirmations: 1, value: 30000 }
      ])
      const result = inputs.sort((a, b) => a.ascentCompareWeighted(b))
      const expected = [0, 0, 1, 20000, 30000, 300000, 50000]
      expect(result.map((x) => x.value)).toEqual(expected)
    })
  })

  describe('descentDraw', () => {
    it('should return the right selection', () => {
      const inputs = map(Coin.fromJS, [
        { value: 1 },
        { value: 20000 },
        { value: 0 },
        { value: 0 },
        { value: 300000 },
        { value: 50000 },
        { value: 30000 }
      ])
      const targets = map(Coin.fromJS, [{ value: 100000 }])
      const selection = cs.descentDraw(targets, 55, inputs, 'change-address')
      expect(selection.inputs.map((x) => x.value)).toEqual([300000])

      // (overhead + inputs + outputs) * feePerByte
      // (10 + (1 * 148) + (2 * 34)) * 55 = 12430
      expect(selection.fee).toEqual(12430)
      // change = inputs - outputs - fee
      //          300000 - 100000 - 12430 = 187570
      expect(selection.outputs.map((x) => x.value)).toEqual([100000, 187570])
    })
    it('should demote unconfirmed coins', () => {
      const inputs = map(Coin.fromJS, [
        { confirmations: 1, value: 1 },
        { confirmations: 1, value: 20000 },
        { confirmations: 1, value: 0 },
        { confirmations: 1, value: 0 },
        { confirmations: 0, value: 300000 },
        { confirmations: 1, value: 50000 },
        { confirmations: 1, value: 30000 }
      ])
      const targets = map(Coin.fromJS, [{ value: 1000 }])
      const selection = cs.descentDraw(targets, 55, inputs, 'change-address')
      expect(selection.inputs.map((x) => x.value)).toEqual([50000])

      // (overhead + inputs + outputs) * feePerByte
      // (10 + (1 * 148) + (2 * 34)) * 55 = 12430
      expect(selection.fee).toEqual(12430)
      // change = inputs - outputs - fee
      //          50000 - 1000 - 12430 = 36570
      expect(selection.outputs.map((x) => x.value)).toEqual([1000, 36570])
    })
  })

  describe('ascentDraw', () => {
    it('should return the right selection', () => {
      const inputs = map(Coin.fromJS, [
        { value: 1 },
        { value: 20000 },
        { value: 0 },
        { value: 0 },
        { value: 300000 },
        { value: 50000 },
        { value: 30000 }
      ])
      const targets = map(Coin.fromJS, [{ value: 100000 }])
      const selection = cs.ascentDraw(targets, 55, inputs, 'change-address')
      expect(selection.inputs.map((x) => x.value)).toEqual([20000, 30000, 50000, 300000])

      // (overhead + inputs + outputs) * feePerByte
      // (10 + (4 * 148) + (2 * 34)) * 55 = 36850
      expect(selection.fee).toEqual(36850)
      // change = inputs - outputs - fee
      //          400000 - 100000 - 36850 = 263150
      expect(selection.outputs.map((x) => x.value)).toEqual([100000, 263150])
    })
  })

  describe('singleRandomDraw', () => {
    it('should return the right selection', () => {
      const seed = 'test-seed'
      const inputs = map(Coin.fromJS, [
        { value: 1 },
        { value: 20000 },
        { value: 0 },
        { value: 0 },
        { value: 300000 },
        { value: 50000 },
        { value: 30000 }
      ])
      const targets = map(Coin.fromJS, [{ value: 60000 }])
      const selection = cs.singleRandomDraw(targets, 55, inputs, 'change-address', seed)
      expect(selection.fee).toEqual(20000)
      expect(selection.inputs.map((x) => x.value)).toEqual([30000, 50000])
      expect(selection.outputs.map((x) => x.value)).toEqual([60000])
    })
  })
})import * as Coin from './coinSelection/coin'
import * as Exchange from './exchange'
import * as Network from './network'
import * as pairing from './pairing'
import * as coreActions from './redux/actions'
import * as coreActionsTypes from './redux/actionTypes'
import * as coreMiddleware from './redux/middleware'
import * as paths from './redux/paths'
import * as coreReducers from './redux/reducers'
import coreRootSagaFactory from './redux/rootSaga'
import coreSagasFactory from './redux/sagas'
import * as coreSelectors from './redux/selectors'
import Remote from './remote'
import * as transactions from './transactions'
import * as Types from './types'
import * as utils from './utils'
import * as crypto from './walletCrypto'

export {
  Coin,
  coreActions,
  coreActionsTypes,
  coreMiddleware,
  coreReducers,
  coreRootSagaFactory,
  coreSagasFactory,
  coreSelectors,
  crypto,
  Exchange,
  Network,
  pairing,
  paths,
  Remote,
  transactions,
  Types,
  utils
}import { format, getUnixTime, isSameYear } from 'date-fns'
import { curry, equals, includes, lift, map, toLower } from 'ramda'

import { EthRawTxType } from '@core/network/api/eth/types'
import { calculateFee } from '@core/utils/eth'

import {
  getDefaultAddress,
  getDefaultLabel,
  getErc20TxNote,
  getEthTxNote
} from '../redux/kvStore/eth/selectors'
import Remote from '../remote'

//
// Shared Utils
//
export const getTime = (timeStamp: number | Date) => {
  const date = new Date(getUnixTime(timeStamp) * 1000)
  return isSameYear(date, new Date())
    ? format(date, 'MMMM d @ h:mm a')
    : format(date, 'MMMM d yyyy @ h:mm a')
}

const getType = (tx, addresses) => {
  const lowerAddresses = map(toLower, addresses)

  switch (true) {
    case includes(tx.from, lowerAddresses) && includes(tx.to, lowerAddresses):
      return 'Transferred'
    case includes(tx.from, lowerAddresses):
      return 'Sent'
    case includes(tx.to, lowerAddresses):
      return 'Received'
    default:
      return 'Unknown'
  }
}

//
// ETH
//

export const getLabel = (address, state) => {
  const defaultLabelR = getDefaultLabel(state)
  const defaultAddressR = getDefaultAddress(state)
  const transform = (defaultLabel, defaultAddress) => {
    switch (true) {
      case equals(toLower(defaultAddress), toLower(address)):
        return defaultLabel
      default:
        return address
    }
  }
  const labelR = lift(transform)(defaultLabelR, defaultAddressR)
  return labelR.getOrElse(address)
}

export const _transformTx = curry((addresses, erc20Contracts, state, tx: EthRawTxType) => {
  const fee = calculateFee(tx.gasPrice, tx.state === 'CONFIRMED' ? tx.gasUsed : tx.gasLimit, false)
  const type = toLower(getType(tx, addresses))
  const amount =
    type === 'sent' ? parseInt(tx.value, 10) + parseInt(fee, 10) : parseInt(tx.value, 10)
  // @ts-ignore
  const time = tx.timestamp || tx.timeStamp
  const isErc20 = includes(tx.to, erc20Contracts.map(toLower))

  return {
    amount,
    blockHeight: tx.state === 'CONFIRMED' ? tx.blockNumber : undefined,
    data: isErc20 ? tx.data : null,
    description: getEthTxNote(state, tx.hash).getOrElse(''),
    erc20: isErc20,
    fee: Remote.Success(fee),
    from: getLabel(tx.from, state),
    hash: tx.hash,
    insertedAt: Number(time) * 1000,
    state: tx.state,
    time,
    timeFormatted: getTime(new Date(time * 1000)),
    to: getLabel(tx.to, state),
    type
  }
})

//
// ERC20
//
export const getErc20Label = (address, token, state) => {
  const ethAddressR = getDefaultAddress(state)
  const transform = (ethAddress) => {
    if (equals(toLower(ethAddress), toLower(address))) {
      return `${token} DeFi Wallet`
    }
    return address
  }
  const labelR = lift(transform)(ethAddressR)
  return labelR.getOrElse(address)
}

export const _transformErc20Tx = curry((addresses, state, token, tx) => {
  const type = toLower(getType(tx, addresses))
  const time = tx.timestamp || tx.timeStamp

  return {
    amount: parseInt(tx.value, 10),
    blockHeight: tx.blockNumber,
    coin: token,
    description: getErc20TxNote(state, token, tx.transactionHash).getOrElse(''),
    fee: Remote.NotAsked,
    from: getErc20Label(tx.from, token, state),
    hash: tx.transactionHash,
    insertedAt: Number(time) * 1000,
    state: tx.state,
    time,
    timeFormatted: getTime(new Date(time * 1000)),
    to: getErc20Label(tx.to, token, state),
    type
  }
})

export const transformTx = _transformTx
export const transformErc20Tx = _transformErc20Tximport { format, getUnixTime, isSameYear } from 'date-fns'
import {
  allPass,
  always,
  compose,
  curry,
  equals,
  find,
  findIndex,
  ifElse,
  isNil,
  lensIndex,
  lensProp,
  mapAccum,
  not,
  over,
  prop,
  propEq,
  propOr,
  propSatisfies,
  toLower,
  view
} from 'ramda'

import Remote from '../remote'
import {
  Address,
  AddressBook,
  AddressBookEntry,
  AddressMap,
  HDAccount,
  HDAccountList,
  HDWallet,
  HDWalletList,
  TXNotes,
  Wallet
} from '../types'

const unpackInput = prop('prev_out')
const isLegacy = (wallet, coin) =>
  compose(not, isNil, AddressMap.selectAddress(prop('addr', coin)), Wallet.selectAddresses)(wallet)
const isAccount = (coin) => !!coin.xpub
const isAccountChange = (x) => isAccount(x) && x.xpub.path.split('/')[1] === '1'
const accountPath = (index, coin) => index + coin.xpub.path.substr(1)
const receiveIndex = (coin) => {
  if (!coin || !coin.xpub || !coin.xpub.path) return
  if (!coin.xpub.path.split('/').length === 3) return
  return parseInt(coin.xpub.path.substr(1).split('/')[2])
}
const isCoinBase = (inputs) => inputs.length === 1 && inputs[0].prev_out == null

const tagCoin = curry((wallet, accountList, coin) => {
  switch (true) {
    case isAccount(coin):
      const account =
        compose(
          HDAccountList.selectByXpub(coin.xpub.m),
          HDWallet.selectAccounts,
          HDWalletList.selectHDWallet,
          Wallet.selectHdWallets
        )(wallet) || compose(HDAccountList.selectByXpub(coin.xpub.m))(accountList)
      const index = HDAccount.selectIndex(account)
      return {
        accountIndex: index,
        address: coin.addr,
        amount: coin.value,
        change: isAccountChange(coin),
        coinType: accountPath(index, coin),
        label: HDAccount.selectLabel(account),
        // TODO: SEGWIT, is this needed?
        // isWatchOnly: HDAccount.isWatchOnly(account),
        receiveIndex: receiveIndex(coin) // only if change?
      }
    case isLegacy(wallet, coin):
      const address = compose(AddressMap.selectAddress(coin.addr), Wallet.selectAddresses)(wallet)
      return {
        address: coin.addr,
        amount: coin.value,
        change: false,
        coinType: 'legacy',
        isWatchOnly: Address.isWatchOnly(address),
        label: Address.selectLabel(address)
      }
    default:
      const bookEntry = compose(
        AddressBook.selectAddressLabel(coin.addr),
        Wallet.selectAddressBook
      )(wallet)
      return {
        address: coin.addr,
        amount: coin.value,
        change: false,
        coinType: 'external',
        isWatchOnly: false,
        label: bookEntry ? AddressBookEntry.selectLabel(bookEntry) : null
      }
  }
})

const txtype = (result, fee) => {
  const impact = result + fee
  switch (true) {
    case impact === 0:
      return 'Transferred'
    case result < 0:
      return 'Sent'
    case result > 0:
      return 'Received'
    default:
      return 'Unknown'
  }
}

// amount is what we show on the transaction feed
// result is internalreceive - internalspend
const computeAmount = (type, inputData, outputData) => {
  switch (type) {
    case 'Transferred':
      return propOr(0, 'internal', outputData) - propOr(0, 'change', outputData)
    case 'Sent':
      return -propOr(0, 'internal', outputData) + propOr(0, 'internal', inputData)
    case 'Received':
      return propOr(0, 'internal', outputData) - propOr(0, 'internal', inputData)
    default:
      return propOr(0, 'internal', outputData) - propOr(0, 'internal', inputData)
  }
}

const init = {
  change: 0,
  internal: 0,
  isWatchOnly: false,
  total: 0
}

// internalAmount :: taggedCoin -> Integer
const internalAmount = ifElse(
  propSatisfies((x) => x !== 'external', 'coinType'),
  prop('amount'),
  always(0)
)

const changeAmount = ifElse(propEq('change', true), prop('amount'), always(0))

const reduceCoins = (acc, taggedCoin) => {
  return {
    change: acc.change + changeAmount(taggedCoin),
    internal: acc.internal + internalAmount(taggedCoin),
    isWatchOnly: acc.isWatchOnly || taggedCoin.isWatchOnly,
    total: acc.total + taggedCoin.amount
  }
}

const appender = curry((tagger, acc, coin) => {
  const taggedCoin = tagger(coin)
  return [reduceCoins(acc, taggedCoin), taggedCoin]
})

const selectFromAndto = (inputs, outputs, type) => {
  const preceived = compose(not, propEq('coinType', 'external'))
  const psent = compose(not, propEq('address', inputs[0].address))
  const predicate = type === 'Sent' ? psent : preceived
  const myOutput = find(allPass([propEq('change', false), predicate]))(outputs) || outputs[0]
  return {
    from: inputs[0].label || inputs[0].address,
    to: myOutput.label || myOutput.address,
    toAddress: myOutput.address
  }
}

const findLegacyChanges = (inputs, inputData, outputs, outputData) => {
  if (inputs && inputs[0].coinType === 'legacy' && inputData.internal === inputData.total) {
    const { address } = inputs[0]
    const index = findIndex(propEq('address', address))(outputs)
    if (index < 0) return [outputData, outputs] // no change
    const newOutputs = over(compose(lensIndex(index), lensProp('change')), not, outputs)
    const change = view(compose(lensIndex(index), lensProp('amount')), outputs)
    const newOutputData = over(lensProp('change'), (c) => c + change, outputData)
    return [newOutputData, newOutputs]
  }
  return [outputData, outputs]
}

const CoinbaseCoin = (total) => ({
  address: 'Coinbase',
  amount: total,
  change: false,
  coinType: 'external',
  isWatchOnly: false,
  label: 'Coinbase'
})

const CoinBaseData = (total) => ({
  change: 0,
  internal: 0,
  isWatchOnly: false,
  total
})

const getDescription = (hash, txNotes, addressLabels, toAddress) => {
  const txNote = TXNotes.selectNote(hash, txNotes)
  return txNote || propOr('', [toAddress], addressLabels)
}

export const getTime = (tx) => {
  const date = new Date(getUnixTime(tx.time) * 1000)
  return isSameYear(date, new Date())
    ? format(date, 'MMMM d @ h:mm a')
    : format(date, 'MMMM d yyyy @ h:mm a')
}

export const _transformTx = (wallet, accountList, txNotes, addressLabels, tx) => {
  const type = txtype(tx.result, tx.fee)
  const inputTagger = compose(tagCoin(wallet, accountList), unpackInput)
  const outputTagger = tagCoin(wallet, accountList)
  const [oData, outs] = mapAccum(appender(outputTagger), init, prop('out', tx))
  const [inputData, inputs] = ifElse(
    compose(isCoinBase, prop('inputs')),
    always([CoinBaseData(oData.total), [CoinbaseCoin(oData.total)]]),
    (t) => mapAccum(appender(inputTagger), init, prop('inputs', t))
  )(tx)

  const [outputData, outputs] = findLegacyChanges(inputs, inputData, outs, oData)
  const { from, to, toAddress } = selectFromAndto(inputs, outputs, type)

  return {
    amount: computeAmount(type, inputData, outputData),
    blockHeight: tx.block_height,
    coin: 'BTC',
    description: getDescription(tx.hash, txNotes, addressLabels, toAddress),
    double_spend: tx.double_spend,
    fee: Remote.Success(tx.fee),
    from,
    fromWatchOnly: inputData.isWatchOnly,
    hash: tx.hash,
    inputs,
    insertedAt: tx.time * 1000,
    outputs,
    rbf: tx.rbf,
    time: tx.time,
    timeFormatted: getTime(tx),
    to,
    toAddress,
    toWatchOnly: outputData.isWatchOnly,
    type: toLower(type)
  }
}

export const transformTx = _transformTximport { format, getUnixTime, isSameYear } from 'date-fns'
import {
  allPass,
  always,
  any,
  compose,
  curry,
  find,
  findIndex,
  ifElse,
  isNil,
  lensIndex,
  lensProp,
  mapAccum,
  not,
  over,
  pathOr,
  prop,
  propEq,
  propOr,
  propSatisfies,
  reject,
  toLower,
  view
} from 'ramda'

import Remote from '../remote'
import {
  Address,
  AddressBook,
  AddressBookEntry,
  AddressMap,
  HDAccount,
  HDAccountList,
  HDWallet,
  HDWalletList,
  Wallet
} from '../types'

const unpackInput = prop('prev_out')
const isLegacy = (wallet, coin) =>
  compose(not, isNil, AddressMap.selectAddress(prop('addr', coin)), Wallet.selectAddresses)(wallet)
const isAccount = (coin) => !!coin.xpub
const isAccountChange = (x) => isAccount(x) && x.xpub.path.split('/')[1] === '1'
const accountPath = (index, coin) => index + coin.xpub.path.substr(1)
const receiveIndex = (coin) => {
  if (!coin || !coin.xpub || !coin.xpub.path) return
  if (!coin.xpub.path.split('/').length === 3) return
  return parseInt(coin.xpub.path.substr(1).split('/')[2])
}
const isDust = propEq('amount', 546)
const isCoinBase = (inputs) => inputs.length === 1 && inputs[0].prev_out == null

const tagCoin = curry((wallet, accountList, coin) => {
  switch (true) {
    case isAccount(coin):
      const account =
        compose(
          HDAccountList.selectByXpub(coin.xpub.m),
          HDWallet.selectAccounts,
          HDWalletList.selectHDWallet,
          Wallet.selectHdWallets
        )(wallet) || compose(HDAccountList.selectByXpub(coin.xpub.m))(accountList)
      const index = HDAccount.selectIndex(account)
      return {
        accountIndex: index,
        address: coin.addr,
        amount: coin.value,
        change: isAccountChange(coin),
        coinType: accountPath(index, coin),
        isWatchOnly: HDAccount.isWatchOnly(account),
        label: HDAccount.selectLabel(account),
        receiveIndex: receiveIndex(coin) // only if change?
      }
    case isLegacy(wallet, coin):
      const address = compose(AddressMap.selectAddress(coin.addr), Wallet.selectAddresses)(wallet)
      return {
        address: coin.addr,
        amount: coin.value,
        change: false,
        coinType: 'legacy',
        isWatchOnly: Address.isWatchOnly(address),
        label: Address.selectLabel(address)
      }
    default:
      const bookEntry = compose(
        AddressBook.selectAddressLabel(coin.addr),
        Wallet.selectAddressBook
      )(wallet)
      return {
        address: coin.addr,
        amount: coin.value,
        change: false,
        coinType: 'external',
        isWatchOnly: false,
        label: bookEntry ? AddressBookEntry.selectLabel(bookEntry) : null
      }
  }
})

const txtype = (result, fee) => {
  const impact = result + fee
  switch (true) {
    case impact === 0:
      return 'Transferred'
    case result < 0:
      return 'Sent'
    case result > 0:
      return 'Received'
    default:
      return 'Unknown'
  }
}

// amount is what we show on the transaction feed
// result is internalreceive - internalspend
const computeAmount = (type, inputData, outputData) => {
  switch (type) {
    case 'Transferred':
      return propOr(0, 'internal', outputData) - propOr(0, 'change', outputData)
    case 'Sent':
      return -propOr(0, 'internal', outputData) + propOr(0, 'internal', inputData)
    case 'Received':
      return propOr(0, 'internal', outputData) - propOr(0, 'internal', inputData)
    default:
      return propOr(0, 'internal', outputData) - propOr(0, 'internal', inputData)
  }
}

const init = {
  change: 0,
  internal: 0,
  isWatchOnly: false,
  total: 0
}

// internalAmount :: taggedCoin -> Integer
const internalAmount = ifElse(
  propSatisfies((x) => x !== 'external', 'coinType'),
  prop('amount'),
  always(0)
)

const changeAmount = ifElse(propEq('change', true), prop('amount'), always(0))

const reduceCoins = (acc, taggedCoin) => {
  return {
    change: acc.change + changeAmount(taggedCoin),
    internal: acc.internal + internalAmount(taggedCoin),
    isWatchOnly: acc.isWatchOnly || taggedCoin.isWatchOnly,
    total: acc.total + taggedCoin.amount
  }
}

const appender = curry((tagger, acc, coin) => {
  const taggedCoin = tagger(coin)
  return [reduceCoins(acc, taggedCoin), taggedCoin]
})

const selectFromAndto = (inputs, outputs, type) => {
  const preceived = compose(not, propEq('coinType', 'external'))
  const psent = compose(not, propEq('address', inputs[0].address))
  const predicate = type === 'Sent' ? psent : preceived
  const myOutput = find(allPass([propEq('change', false), predicate]))(outputs) || outputs[0]
  return {
    from: inputs[0].label || inputs[0].address,
    to: myOutput.label || myOutput.address,
    toAddress: myOutput.address
  }
}

const findLegacyChanges = (inputs, inputData, outputs, outputData) => {
  if (inputs && inputs[0].coinType === 'legacy' && inputData.internal === inputData.total) {
    const { address } = inputs[0]
    const index = findIndex(propEq('address', address))(outputs)
    if (index < 0) return [outputData, outputs] // no change
    const newOutputs = over(compose(lensIndex(index), lensProp('change')), not, outputs)
    const change = view(compose(lensIndex(index), lensProp('amount')), outputs)
    const newOutputData = over(lensProp('change'), (c) => c + change, outputData)
    return [newOutputData, newOutputs]
  }
  return [outputData, outputs]
}

const CoinbaseCoin = (total) => ({
  address: 'Coinbase',
  amount: total,
  change: false,
  coinType: 'external',
  isWatchOnly: false,
  label: 'Coinbase'
})

const CoinBaseData = (total) => ({
  change: 0,
  internal: 0,
  isWatchOnly: false,
  total
})

export const getTime = (tx) => {
  const date = new Date(getUnixTime(tx.time) * 1000)
  return isSameYear(date, new Date())
    ? format(date, 'MMMM d @ h:mm a')
    : format(date, 'MMMM d yyyy @ h:mm a')
}

export const _transformTx = (wallet, accountList = [], txNotes, tx) => {
  const type = txtype(tx.result, tx.fee)
  const inputTagger = compose(tagCoin(wallet, accountList), unpackInput)
  const outputTagger = tagCoin(wallet, accountList)
  const [oData, outs] = mapAccum(appender(outputTagger), init, prop('out', tx))
  // eslint-disable-next-line prefer-const
  let [inputData, inputs] = ifElse(
    compose(isCoinBase, prop('inputs')),
    always([CoinBaseData(oData.total), [CoinbaseCoin(oData.total)]]),
    (t) => mapAccum(appender(inputTagger), init, prop('inputs', t))
  )(tx)

  // eslint-disable-next-line prefer-const
  let [outputData, outputs] = findLegacyChanges(inputs, inputData, outs, oData)

  if (any(isDust, inputs) && any(isDust, outputs)) {
    inputs = reject(isDust, inputs)
    outputs = reject(isDust, outputs)
  }
  const { from, to, toAddress } = selectFromAndto(inputs, outputs, type)

  return {
    amount: computeAmount(type, inputData, outputData),
    blockHeight: tx.block_height,
    coin: 'BCH',
    description: pathOr('', [tx.hash], txNotes),
    double_spend: tx.double_spend,
    fee: Remote.Success(tx.fee),
    from,
    fromWatchOnly: inputData.isWatchOnly,
    hash: tx.hash,
    inputs,
    insertedAt: tx.time * 1000,
    outputs,
    time: tx.time,
    timeFormatted: getTime(tx),
    to,
    toAddress,
    toWatchOnly: outputData.isWatchOnly,
    type: toLower(type)
  }
}

export const transformTx = _transformTximport { format, getUnixTime, isSameYear } from 'date-fns'{
  "v4": "{\"pbkdf2_iterations\":5000,\"version\":4,\"payload\":\"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\"}",
  "v3": "{\"pbkdf2_iterations\":1200,\"version\":3,\"payload\":\"kukyY90NSHqACGjLxFRYxvUsYv5rH2jVY6jwNW8juINDIQyZ9PCxfxPOt1a1oXBecu3Fi8OkWBVsgQdcagrnxJardzlPdKn+x7nFJLEIzGZcKpUATI1wrWLpR1ViRKJnotpwTdBhAJq5DxOsw0IhCf7mP/sOA8PThsnqSX13yVOTao7QPMz55UmE/kJmeGfYDe/1BeX8FAADW5URFLphzNt14FnSw+SXQ/AfIJb1/L7ZF49sl2H+V/a/sJXan3oWrLLzjgogdnnfAqU+joSPJUaZMUZ9KT1w2MU77RAvGK7Itwfyyk+xubTZV/zC4o84PNkAQiJhpz5UFzpqVwYzxweIXx6dxHw6Ox4XFLEQpUgiVt8Acsg+kcFKQIVIc7BnFczyZhgKKD8J3fJGw1/pumW3rA6u1EnFqEOy2b1SrMDFflG1ZawFFiJwZE9+rGT4NqPfsAhqR7B5XWYkexK56w7PEiJ/Dxv+z7JCurvDjsvefAOcDVkhuID9rOYFBxc01EtdMeFpS/Ts6dAv7EMLHC7qzXrpQiwPYuLYElTmUvSnJXtTENQDCmkuiep0588SHqSLY/xFyIGXaW+riZLw4WQgVxK4/EeiPEWDiFUAHYFlOWAlz1dv5obxOa8aLp+EPg38O7rX+itHwTI1JcECkHRJZxqKGmyGFz1DtakqyFMuMfnGOE+HpxpZs6mGvs0Fqh2cjaJo0FDkCrUFGFVPFAKRU5SPbzINGjpvHy47mCHMa6uVpJ7+LK93dml1fcQAcIfWwes6igqDrArE99usK8H11bd99Mz5MVIW96z7PtZgVVIPx9uo+S8DbMIKsMqGUhqqMdKZA6zvZwK9OOLxdnHeSpJVRPTGpeOJZPHHPR2qIqgSD+uC0cN9XORQjx6tKxv5LPHlQKB1n3MyeoDSrId//bCCvzZZRtiC8ZnHzmi89ss7Ft7bIP2URLyb3gUXJXkckLqvJfGmzuXE10jUBjAI4ERJCfekPWyLnFg9JPj4Tr5q5CpHyaqqhHkUOgxhmWEYWUEs54UO/+Vu+n5rF3X4Eqh6aYrfFenQz+mGT9uO8X+fkV4Buaj/wftuEV2w91oiaPf3nV7brTNx68pEN1svkDnMG1GWK68BDPO6xD/dGc7J1XD2tnfaF2n3mHiA/EmItyktV50Gj0bv3QpDz5tUavUuN97KEEOJDsvGKnZd01gnsPxGN8GFq/6ty0GAWx9pjgJ13r2Y1lQsaz/aJThVopq0ZVTQz9Hl277d7FZ0erdRLQSgfTFR3g4oDDaa0C1qmnotmf8d6l0tVoxIUig+IJu7QaNJzUbPizqanU8P9HcN18a2DdxuTJRzd+93W4xQ0q3awel1IWhSkrkVZ2K2sYwyWGgssoHxGw4KwvyS/NHkFsXNTCFlQwZqSxYHj3VM7kn8jk7K8VbxkX3tzqqKwKkBoJIgYunGBQLErAj5nZJDMxTNR+a+SE8KkHQmEhwMLHtcTkuFoc/4xdLW9Qsokirp0XjKPLNEFjnItAiMzoW90DqK/MRUeuOciuvVa0zwxy0MG7HLjDY683esrR1lgXp+kPzetQGoWoQJsUqqzUV4P5aksnra8gFw4EDHgBUjpIWDpOJXG5OUfvXw+mWUVR7FA/9INPpIo2t3B/Y6rK0eNwz3xATVHFTDgWdu8KBddlHOVhHUPZpeI9YX7mlTV5g49SpKrzO/42OumITkjYMujMsOX2jtNmTJ08fy\"}",
  "v2": "{\"pbkdf2_iterations\":5000,\"version\":2,\"payload\":\"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\"}",
  "v1": "0/oL4idvgbM/uj8m4MyXtBGaENMRhRqpOazjWFkvZusy4gnBCgGg0Ree5rkxlkYlY+R1z+OZ6YfTJkWiWFn56HG2cqOrEgk6N3CtTwmseCl3BfwXF8dS6dhA/5AetBvepOLgQ7E8LF3egQSzYzdHEbKxG4Ml5H8FXzV1nSfHfVrsaQYeGxDv2YMdszpd6mJ3MKqGuNPBpcxM1c9v9EjTMOxICVXIkW5MZSbq/i6zzHIfmDshg2rmkj3ZxtV1vG2wwSgGE5rcxtgno0nwq3GVnWv1+oT9Tt8Y9EZCCJQWD/I7mf7rF030oMXUNL17jNFZKaeGG81QRPb7fAMJC8B0K6ERfKVa4/Tap9UVj+wnrMt19Xzbew5c8zLjXK16yt9ZsEvSEEJsE+TtUqR7pUKYRGDasE6419LzDFcdNJZ73Q2ujdqafJ/JQot6T6FyySRHw7fAA/lPoU1q/0/E5YhM2AQq/MoNj1NppuGdZT/xttNqaMjC9CgP+Sf3Jt9m8Fap1V27oTAP25o5jt175LixnluHXF2RP/Hg7xdzCxIjvpEVVYlZ0HwyOKwRb6KsJDBTm5QGdlaeP42wYNjVlk/bY7gTzdF3dJ4Daf7ITp9KzJYjgFap19TLAtAi9U0d0uGpWSVjDEp9wlg1tnCEtXqpEl93/nzpi/R/G/BcbNHV5ciLgkdslBQqvzTq/E79kAuXeNKbmNJWuljSoUNpyD4c4AFSaUpCIpG+edqNexavl357nyt0ackZfM3huQ9wjYiMJgTy00Hb31niY1Ua3iWoIlHrDWeBbGzqI1a+mylAzNqzvARE0A1dyjhRchtoy2vOyUUoJBKxw6YRgE0pZbk3lqY4RYznAaOFS6SJtUYMJBfz5KFpqzRVESYCK2mSgXul/lpt5emUZI1XtRdD4zBzaSbG0wHcEqn/woCOA9NlJZArpjoE6mv5emK/BOAG3xZkklsCR5Msz3NyltmU8QmjfxvuN+Vyvdh907QtFF1RCLLPzDFTR6BAIXo0klXWw166n53zyi2FfPfCwUwCh4a7hYoiuqecfuBTsX8PBhjL3E6+kMktFeBzKGl9BqWnlobOd7QsPGPj16mvQnKip1ay04/B8XiSl+Ye4deYqng/hPtHNApopWwhQ4sS6drEwJ8vNmznkcod7NZnhjcUHqiemD6REqHZVoEB69WC2TPDQPEGNM3HhSYstwU2cFyrQ5m+cxemt/5dNBMc5jO2IPzcLdSNgePGiaX+9WTVJo44t5vOKmX+ekSP9EG7YluxrB7l"
}import assert from 'assert'
import * as crypto from 'crypto'

export const SALT_BYTES = 16
export const AUTH_TAG_BYTES = 16
export const KEY_BIT_LEN = 256
export const BLOCK_BIT_LEN = 128

export const NoPadding = {
  /*
   *   Does nothing
   */

  pad(dataBytes) {
    return dataBytes
  },

  unpad(dataBytes) {
    return dataBytes
  }
}

export const ZeroPadding = {
  /*
   *   Fills remaining block space with 0x00 bytes
   *   May cause issues if data ends with any 0x00 bytes
   */

  pad(dataBytes, nBytesPerBlock) {
    const nPaddingBytes = nBytesPerBlock - (dataBytes.length % nBytesPerBlock)
    const zeroBytes = Buffer.from(nPaddingBytes).fill(0x00)
    return Buffer.concat([dataBytes, zeroBytes])
  },

  unpad(dataBytes) {
    const unpaddedHex = dataBytes.toString('hex').replace(/(00)+$/, '')
    return Buffer.from(unpaddedHex, 'hex')
  }
}

export const Iso10126 = {
  /*
   *   Fills remaining block space with random byte values, except for the
   *   final byte, which denotes the byte length of the padding
   */
  pad(dataBytes, nBytesPerBlock) {
    const nPaddingBytes = nBytesPerBlock - (dataBytes.length % nBytesPerBlock)
    const paddingBytes = crypto.randomBytes(nPaddingBytes - 1)
    const endByte = Buffer.from([nPaddingBytes])

    return Buffer.concat([dataBytes, paddingBytes, endByte])
  },
  unpad(dataBytes) {
    const nPaddingBytes = dataBytes[dataBytes.length - 1]

    return dataBytes.slice(0, -nPaddingBytes)
  }
}

export const Iso97971 = {
  /*
   *   Fills remaining block space with 0x00 bytes following a 0x80 byte,
   *   which serves as a mark for where the padding begins
   */

  pad(dataBytes, nBytesPerBlock) {
    const withStartByte = Buffer.concat([dataBytes, Buffer.from([0x80])])
    return ZeroPadding.pad(withStartByte, nBytesPerBlock)
  },

  unpad(dataBytes) {
    const zeroBytesRemoved = ZeroPadding.unpad(dataBytes)
    return zeroBytesRemoved.slice(0, zeroBytesRemoved.length - 1)
  }
}

export const AES = {
  CBC: 'aes-256-cbc',
  ECB: 'aes-256-ecb',
  GCM: 'aes-256-gcm',
  OFB: 'aes-256-ofb',

  decrypt(dataBytes, key, salt, options) {
    options = options || {}
    assert(Buffer.isBuffer(dataBytes), 'expected `dataBytes` to be a Buffer')
    assert(Buffer.isBuffer(key), 'expected `key` to be a Buffer')
    assert(Buffer.isBuffer(salt) || salt === null, 'expected `salt` to be a Buffer or null')

    const decipher = crypto.createDecipheriv(options.mode || AES.CBC, key, salt || '')
    decipher.setAutoPadding(!options.padding)

    let data = dataBytes
    if (options.mode === AES.GCM) {
      const tag = dataBytes.slice(dataBytes.length - 16)
      decipher.setAuthTag(tag)
      data = dataBytes.slice(0, dataBytes.length - 16)
    }

    let decryptedBytes = Buffer.concat([decipher.update(data), decipher.final()])

    if (options.padding) decryptedBytes = options.padding.unpad(decryptedBytes)
    return decryptedBytes
  },

  /*
   *   Encrypt / Decrypt with aes-256
   *   - dataBytes, key, and salt are expected to be buffers
   *   - default options are mode=CBC and padding=auto (PKCS7)
   */
  encrypt(dataBytes, key, salt, options) {
    options = options || {}
    assert(Buffer.isBuffer(dataBytes), 'expected `dataBytes` to be a Buffer')
    assert(Buffer.isBuffer(key), 'expected `key` to be a Buffer')
    assert(Buffer.isBuffer(salt) || salt === null, 'expected `salt` to be a Buffer or null')

    const cipher = crypto.createCipheriv(options.mode || AES.CBC, key, salt || '')
    cipher.setAutoPadding(!options.padding)

    if (options.padding) {
      dataBytes = options.padding.pad(dataBytes, BLOCK_BIT_LEN / 8)
    }
    const encryptedBytes = Buffer.concat([cipher.update(dataBytes), cipher.final()])

    return options.mode === AES.GCM
      ? Buffer.concat([encryptedBytes, cipher.getAuthTag()])
      : { encryptedBytes }
  }
}  "v4": "{\"pbkdf2_iterations\":5000,\"version\":4,\"payload\":\"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\"}",
  "v3": "{\"pbkdf2_iterations\":1200,\"version\":3,\"payload\":\"kukyY90NSHqACGjLxFRYxvUsYv5rH2jVY6jwNW8juINDIQyZ9PCxfxPOt1a1oXBecu3Fi8OkWBVsgQdcagrnxJardzlPdKn+x7nFJLEIzGZcKpUATI1wrWLpR1ViRKJnotpwTdBhAJq5DxOsw0IhCf7mP/sOA8PThsnqSX13yVOTao7QPMz55UmE/kJmeGfYDe/1BeX8FAADW5URFLphzNt14FnSw+SXQ/AfIJb1/L7ZF49sl2H+V/a/sJXan3oWrLLzjgogdnnfAqU+joSPJUaZMUZ9KT1w2MU77RAvGK7Itwfyyk+xubTZV/zC4o84PNkAQiJhpz5UFzpqVwYzxweIXx6dxHw6Ox4XFLEQpUgiVt8Acsg+kcFKQIVIc7BnFczyZhgKKD8J3fJGw1/pumW3rA6u1EnFqEOy2b1SrMDFflG1ZawFFiJwZE9+rGT4NqPfsAhqR7B5XWYkexK56w7PEiJ/Dxv+z7JCurvDjsvefAOcDVkhuID9rOYFBxc01EtdMeFpS/Ts6dAv7EMLHC7qzXrpQiwPYuLYElTmUvSnJXtTENQDCmkuiep0588SHqSLY/xFyIGXaW+riZLw4WQgVxK4/EeiPEWDiFUAHYFlOWAlz1dv5obxOa8aLp+EPg38O7rX+itHwTI1JcECkHRJZxqKGmyGFz1DtakqyFMuMfnGOE+HpxpZs6mGvs0Fqh2cjaJo0FDkCrUFGFVPFAKRU5SPbzINGjpvHy47mCHMa6uVpJ7+LK93dml1fcQAcIfWwes6igqDrArE99usK8H11bd99Mz5MVIW96z7PtZgVVIPx9uo+S8DbMIKsMqGUhqqMdKZA6zvZwK9OOLxdnHeSpJVRPTGpeOJZPHHPR2qIqgSD+uC0cN9XORQjx6tKxv5LPHlQKB1n3MyeoDSrId//bCCvzZZRtiC8ZnHzmi89ss7Ft7bIP2URLyb3gUXJXkckLqvJfGmzuXE10jUBjAI4ERJCfekPWyLnFg9JPj4Tr5q5CpHyaqqhHkUOgxhmWEYWUEs54UO/+Vu+n5rF3X4Eqh6aYrfFenQz+mGT9uO8X+fkV4Buaj/wftuEV2w91oiaPf3nV7brTNx68pEN1svkDnMG1GWK68BDPO6xD/dGc7J1XD2tnfaF2n3mHiA/EmItyktV50Gj0bv3QpDz5tUavUuN97KEEOJDsvGKnZd01gnsPxGN8GFq/6ty0GAWx9pjgJ13r2Y1lQsaz/aJThVopq0ZVTQz9Hl277d7FZ0erdRLQSgfTFR3g4oDDaa0C1qmnotmf8d6l0tVoxIUig+IJu7QaNJzUbPizqanU8P9HcN18a2DdxuTJRzd+93W4xQ0q3awel1IWhSkrkVZ2K2sYwyWGgssoHxGw4KwvyS/NHkFsXNTCFlQwZqSxYHj3VM7kn8jk7K8VbxkX3tzqqKwKkBoJIgYunGBQLErAj5nZJDMxTNR+a+SE8KkHQmEhwMLHtcTkuFoc/4xdLW9Qsokirp0XjKPLNEFjnItAiMzoW90DqK/MRUeuOciuvVa0zwxy0MG7HLjDY683esrR1lgXp+kPzetQGoWoQJsUqqzUV4P5aksnra8gFw4EDHgBUjpIWDpOJXG5OUfvXw+mWUVR7FA/9INPpIo2t3B/Y6rK0eNwz3xATVHFTDgWdu8KBddlHOVhHUPZpeI9YX7mlTV5g49SpKrzO/42OumITkjYMujMsOX2jtNmTJ08fy\"}",
  "v2": "{\"pbkdf2_iterations\":5000,\"version\":2,\"payload\":\"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\"}",
  "v1": "0/oL4idvgbM/uj8m4MyXtBGaENMRhRqpOazjWFkvZusy4gnBCgGg0Ree5rkxlkYlY+R1z+OZ6YfTJkWiWFn56HG2cqOrEgk6N3CtTwmseCl3BfwXF8dS6dhA/5AetBvepOLgQ7E8LF3egQSzYzdHEbKxG4Ml5H8FXzV1nSfHfVrsaQYeGxDv2YMdszpd6mJ3MKqGuNPBpcxM1c9v9EjTMOxICVXIkW5MZSbq/i6zzHIfmDshg2rmkj3ZxtV1vG2wwSgGE5rcxtgno0nwq3GVnWv1+oT9Tt8Y9EZCCJQWD/I7mf7rF030oMXUNL17jNFZKaeGG81QRPb7fAMJC8B0K6ERfKVa4/Tap9UVj+wnrMt19Xzbew5c8zLjXK16yt9ZsEvSEEJsE+TtUqR7pUKYRGDasE6419LzDFcdNJZ73Q2ujdqafJ/JQot6T6FyySRHw7fAA/lPoU1q/0/E5YhM2AQq/MoNj1NppuGdZT/xttNqaMjC9CgP+Sf3Jt9m8Fap1V27oTAP25o5jt175LixnluHXF2RP/Hg7xdzCxIjvpEVVYlZ0HwyOKwRb6KsJDBTm5QGdlaeP42wYNjVlk/bY7gTzdF3dJ4Daf7ITp9KzJYjgFap19TLAtAi9U0d0uGpWSVjDEp9wlg1tnCEtXqpEl93/nzpi/R/G/BcbNHV5ciLgkdslBQqvzTq/E79kAuXeNKbmNJWuljSoUNpyD4c4AFSaUpCIpG+edqNexavl357nyt0ackZfM3huQ9wjYiMJgTy00Hb31niY1Ua3iWoIlHrDWeBbGzqI1a+mylAzNqzvARE0A1dyjhRchtoy2vOyUUoJBKxw6YRgE0pZbk3lqY4RYznAaOFS6SJtUYMJBfz5KFpqzRVESYCK2mSgXul/lpt5emUZI1XtRdD4zBzaSbG0wHcEqn/woCOA9NlJZArpjoE6mv5emK/BOAG3xZkklsCR5Msz3NyltmU8QmjfxvuN+Vyvdh907QtFF1RCLLPzDFTR6BAIXo0klXWw166n53zyi2FfPfCwUwCh4a7hYoiuqecfuBTsX8PBhjL3E6+kMktFeBzKGl9BqWnlobOd7QsPGPj16mvQnKip1ay04/B8XiSl+Ye4deYqng/hPtHNApopWwhQ4sS6drEwJ8vNmznkcod7NZnhjcUHqiemD6REqHZVoEB69WC2TPDQPEGNM3HhSYstwU2cFyrQ5m+cxemt/5dNBMc5jO2IPzcLdSNgePGiaX+9WTVJo44t5vOKmX+ekSP9EG7YluxrB7l"  "v4": "{\"pbkdf2_iterations\":5000,\"version\":4,\"payload\":\"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\"}",
  "v3": "{\"pbkdf2_iterations\":1200,\"version\":3,\"payload\":\"kukyY90NSHqACGjLxFRYxvUsYv5rH2jVY6jwNW8juINDIQyZ9PCxfxPOt1a1oXBecu3Fi8OkWBVsgQdcagrnxJardzlPdKn+x7nFJLEIzGZcKpUATI1wrWLpR1ViRKJnotpwTdBhAJq5DxOsw0IhCf7mP/sOA8PThsnqSX13yVOTao7QPMz55UmE/kJmeGfYDe/1BeX8FAADW5URFLphzNt14FnSw+SXQ/AfIJb1/L7ZF49sl2H+V/a/sJXan3oWrLLzjgogdnnfAqU+joSPJUaZMUZ9KT1w2MU77RAvGK7Itwfyyk+xubTZV/zC4o84PNkAQiJhpz5UFzpqVwYzxweIXx6dxHw6Ox4XFLEQpUgiVt8Acsg+kcFKQIVIc7BnFczyZhgKKD8J3fJGw1/pumW3rA6u1EnFqEOy2b1SrMDFflG1ZawFFiJwZE9+rGT4NqPfsAhqR7B5XWYkexK56w7PEiJ/Dxv+z7JCurvDjsvefAOcDVkhuID9rOYFBxc01EtdMeFpS/Ts6dAv7EMLHC7qzXrpQiwPYuLYElTmUvSnJXtTENQDCmkuiep0588SHqSLY/xFyIGXaW+riZLw4WQgVxK4/EeiPEWDiFUAHYFlOWAlz1dv5obxOa8aLp+EPg38O7rX+itHwTI1JcECkHRJZxqKGmyGFz1DtakqyFMuMfnGOE+HpxpZs6mGvs0Fqh2cjaJo0FDkCrUFGFVPFAKRU5SPbzINGjpvHy47mCHMa6uVpJ7+LK93dml1fcQAcIfWwes6igqDrArE99usK8H11bd99Mz5MVIW96z7PtZgVVIPx9uo+S8DbMIKsMqGUhqqMdKZA6zvZwK9OOLxdnHeSpJVRPTGpeOJZPHHPR2qIqgSD+uC0cN9XORQjx6tKxv5LPHlQKB1n3MyeoDSrId//bCCvzZZRtiC8ZnHzmi89ss7Ft7bIP2URLyb3gUXJXkckLqvJfGmzuXE10jUBjAI4ERJCfekPWyLnFg9JPj4Tr5q5CpHyaqqhHkUOgxhmWEYWUEs54UO/+Vu+n5rF3X4Eqh6aYrfFenQz+mGT9uO8X+fkV4Buaj/wftuEV2w91oiaPf3nV7brTNx68pEN1svkDnMG1GWK68BDPO6xD/dGc7J1XD2tnfaF2n3mHiA/EmItyktV50Gj0bv3QpDz5tUavUuN97KEEOJDsvGKnZd01gnsPxGN8GFq/6ty0GAWx9pjgJ13r2Y1lQsaz/aJThVopq0ZVTQz9Hl277d7FZ0erdRLQSgfTFR3g4oDDaa0C1qmnotmf8d6l0tVoxIUig+IJu7QaNJzUbPizqanU8P9HcN18a2DdxuTJRzd+93W4xQ0q3awel1IWhSkrkVZ2K2sYwyWGgssoHxGw4KwvyS/NHkFsXNTCFlQwZqSxYHj3VM7kn8jk7K8VbxkX3tzqqKwKkBoJIgYunGBQLErAj5nZJDMxTNR+a+SE8KkHQmEhwMLHtcTkuFoc/4xdLW9Qsokirp0XjKPLNEFjnItAiMzoW90DqK/MRUeuOciuvVa0zwxy0MG7HLjDY683esrR1lgXp+kPzetQGoWoQJsUqqzUV4P5aksnra8gFw4EDHgBUjpIWDpOJXG5OUfvXw+mWUVR7FA/9INPpIo2t3B/Y6rK0eNwz3xATVHFTDgWdu8KBddlHOVhHUPZpeI9YX7mlTV5g49SpKrzO/42OumITkjYMujMsOX2jtNmTJ08fy\"}",
  "v2": "{\"pbkdf2_iterations\":5000,\"version\":2,\"payload\":\"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\"}",
  "v1": "0/oL4idvgbM/uj8m4MyXtBGaENMRhRqpOazjWFkvZusy4gnBCgGg0Ree5rkxlkYlY+R1z+OZ6YfTJkWiWFn56HG2cqOrEgk6N3CtTwmseCl3BfwXF8dS6dhA/5AetBvepOLgQ7E8LF3egQSzYzdHEbKxG4Ml5H8FXzV1nSfHfVrsaQYeGxDv2YMdszpd6mJ3MKqGuNPBpcxM1c9v9EjTMOxICVXIkW5MZSbq/i6zzHIfmDshg2rmkj3ZxtV1vG2wwSgGE5rcxtgno0nwq3GVnWv1+oT9Tt8Y9EZCCJQWD/I7mf7rF030oMXUNL17jNFZKaeGG81QRPb7fAMJC8B0K6ERfKVa4/Tap9UVj+wnrMt19Xzbew5c8zLjXK16yt9ZsEvSEEJsE+TtUqR7pUKYRGDasE6419LzDFcdNJZ73Q2ujdqafJ/JQot6T6FyySRHw7fAA/lPoU1q/0/E5YhM2AQq/MoNj1NppuGdZT/xttNqaMjC9CgP+Sf3Jt9m8Fap1V27oTAP25o5jt175LixnluHXF2RP/Hg7xdzCxIjvpEVVYlZ0HwyOKwRb6KsJDBTm5QGdlaeP42wYNjVlk/bY7gTzdF3dJ4Daf7ITp9KzJYjgFap19TLAtAi9U0d0uGpWSVjDEp9wlg1tnCEtXqpEl93/nzpi/R/G/BcbNHV5ciLgkdslBQqvzTq/E79kAuXeNKbmNJWuljSoUNpyD4c4AFSaUpCIpG+edqNexavl357nyt0ackZfM3huQ9wjYiMJgTy00Hb31niY1Ua3iWoIlHrDWeBbGzqI1a+mylAzNqzvARE0A1dyjhRchtoy2vOyUUoJBKxw6YRgE0pZbk3lqY4RYznAaOFS6SJtUYMJBfz5KFpqzRVESYCK2mSgXul/lpt5emUZI1XtRdD4zBzaSbG0wHcEqn/woCOA9NlJZArpjoE6mv5emK/BOAG3xZkklsCR5Msz3NyltmU8QmjfxvuN+Vyvdh907QtFF1RCLLPzDFTR6BAIXo0klXWw166n53zyi2FfPfCwUwCh4a7hYoiuqecfuBTsX8PBhjL3E6+kMktFeBzKGl9BqWnlobOd7QsPGPj16mvQnKip1ay04/B8XiSl+Ye4deYqng/hPtHNApopWwhQ4sS6drEwJ8vNmznkcod7NZnhjcUHqiemD6REqHZVoEB69WC2TPDQPEGNM3HhSYstwU2cFyrQ5m+cxemt/5dNBMc5jO2IPzcLdSNgePGiaX+9WTVJo44t5vOKmX+ekSP9EG7YluxrB7l"
}import BigInteger from 'bigi'
import * as Bitcoin from 'bitcoinjs-lib'
import Base58 from 'bs58'
import scrypt from 'scrypt-js'

import * as utils from '../utils'
import * as WalletCrypto from './utils'

const {
  crypto: { hash256 }
} = Bitcoin

export const parseBIP38toECPair = function (base58Encrypted, passphrase, network) {
  import('unorm').then((Unorm) => {
    let hex

    // Unicode NFC normalization
    passphrase = Unorm.nfc(passphrase)

    try {
      hex = Base58.decode(base58Encrypted)
    } catch (e) {
      throw new Error('Invalid Private Key')
    }

    if (hex.length !== 43) {
      throw new Error('Invalid Private Key')
    } else if (hex[0] !== 0x01) {
      throw new Error('Invalid Private Key')
    }

    const expChecksum = hex.slice(-4)
    hex = hex.slice(0, -4)

    let checksum = hash256(hex)

    if (
      checksum[0] !== expChecksum[0] ||
      checksum[1] !== expChecksum[1] ||
      checksum[2] !== expChecksum[2] ||
      checksum[3] !== expChecksum[3]
    ) {
      throw new Error('Invalid Private Key')
    }

    let isCompPoint = false
    let isECMult = false
    let hasLotSeq = false
    if (hex[1] === 0x42) {
      if (hex[2] === 0xe0) {
        isCompPoint = true
      } else if (hex[2] !== 0xc0) {
        throw new Error('Invalid Private Key')
      }
    } else if (hex[1] === 0x43) {
      isECMult = true
      isCompPoint = (hex[2] & 0x20) !== 0
      hasLotSeq = (hex[2] & 0x04) !== 0
      if ((hex[2] & 0x24) !== hex[2]) {
        throw new Error('Invalid Private Key')
      }
    } else {
      throw new Error('Invalid Private Key')
    }
    let decrypted
    const AESopts = { mode: WalletCrypto.AES.ECB, padding: WalletCrypto.NoPadding }

    const verifyHashAndReturn = function () {
      const tmpkey = Bitcoin.ECPair.fromPrivateKey(decrypted, null, {
        compressed: isCompPoint,
        network
      })

      const base58Address = utils.btc.keyPairToAddress(tmpkey)

      checksum = hash256(base58Address)

      if (
        checksum[0] !== hex[3] ||
        checksum[1] !== hex[4] ||
        checksum[2] !== hex[5] ||
        checksum[3] !== hex[6]
      ) {
        throw new Error('wrong_bip38_pass')
      }
      return tmpkey
    }

    if (!isECMult) {
      const addresshash = Buffer.from(hex.slice(3, 7), 'hex')

      const derivedBytes = scrypt(passphrase, addresshash, 16384, 8, 8, 64)
      var k = derivedBytes.slice(32, 32 + 32)

      const decryptedBytes = WalletCrypto.AES.decrypt(
        Buffer.from(hex.slice(7, 7 + 32), 'hex'),
        k,
        null,
        AESopts
      )
      for (let x = 0; x < 32; x++) {
        decryptedBytes[x] ^= derivedBytes[x]
      }
      decrypted = decryptedBytes

      return verifyHashAndReturn()
    }
    const ownerentropy = hex.slice(7, 7 + 8)
    const ownersalt = Buffer.from(!hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4), 'hex')

    const prefactorA = scrypt(passphrase, ownersalt, 16384, 8, 8, 32)
    let passfactor

    if (!hasLotSeq) {
      passfactor = prefactorA
    } else {
      const prefactorB = Buffer.concat([prefactorA, Buffer.from(ownerentropy, 'hex')])
      passfactor = hash256(prefactorB)
    }

    const passpoint = Bitcoin.ECPair.fromPrivateKey(passfactor).publicKey

    const encryptedpart2 = Buffer.from(hex.slice(23, 23 + 16), 'hex')

    const addresshashplusownerentropy = Buffer.from(hex.slice(3, 3 + 12), 'hex')

    const derived = scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64)
    k = derived.slice(32)

    const unencryptedpart2Bytes = WalletCrypto.AES.decrypt(encryptedpart2, k, null, AESopts)

    for (let i = 0; i < 16; i++) {
      unencryptedpart2Bytes[i] ^= derived[i + 16]
    }

    const encryptedpart1 = Buffer.concat([
      Buffer.from(hex.slice(15, 15 + 8), 'hex'),
      Buffer.from(unencryptedpart2Bytes.slice(0, 0 + 8), 'hex')
    ])

    const unencryptedpart1Bytes = WalletCrypto.AES.decrypt(encryptedpart1, k, null, AESopts)

    for (let ii = 0; ii < 16; ii++) {
      unencryptedpart1Bytes[ii] ^= derived[ii]
    }

    const seedb = Buffer.concat([
      Buffer.from(unencryptedpart1Bytes.slice(0, 0 + 16), 'hex'),
      Buffer.from(unencryptedpart2Bytes.slice(8, 8 + 8), 'hex')
    ])

    const factorb = hash256(seedb)

    // secp256k1: N
    const N = BigInteger.fromHex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

    decrypted = BigInteger.fromBuffer(passfactor)
      .multiply(BigInteger.fromBuffer(factorb))
      .remainder(N)

    return verifyHashAndReturn()
  })
}import BigInteger from 'bigi'
import * as Bitcoin from 'bitcoinjs-lib'
import Base58 from 'bs58'
import scrypt from 'scrypt-js'

import * as utils from '../utils'
import * as WalletCrypto from './utils'

const {
  crypto: { hash256 }
} = Bitcoin

export const parseBIP38toECPair = function (base58Encrypted, passphrase, network) {
  import('unorm').then((Unorm) => {
    let hex

    // Unicode NFC normalization
    passphrase = Unorm.nfc(passphrase)

    try {
      hex = Base58.decode(base58Encrypted)
    } catch (e) {
      throw new Error('Invalid Private Key')
    }

    if (hex.length !== 43) {
      throw new Error('Invalid Private Key')
    } else if (hex[0] !== 0x01) {
      throw new Error('Invalid Private Key')
    }

    const expChecksum = hex.slice(-4)
    hex = hex.slice(0, -4)

    let checksum = hash256(hex)

    if (
      checksum[0] !== expChecksum[0] ||
      checksum[1] !== expChecksum[1] ||
      checksum[2] !== expChecksum[2] ||
      checksum[3] !== expChecksum[3]
    ) {
      throw new Error('Invalid Private Key')
    }

    let isCompPoint = false
    let isECMult = false
    let hasLotSeq = false
    if (hex[1] === 0x42) {
      if (hex[2] === 0xe0) {
        isCompPoint = true
      } else if (hex[2] !== 0xc0) {
        throw new Error('Invalid Private Key')
      }
    } else if (hex[1] === 0x43) {
      isECMult = true
      isCompPoint = (hex[2] & 0x20) !== 0
      hasLotSeq = (hex[2] & 0x04) !== 0
      if ((hex[2] & 0x24) !== hex[2]) {
        throw new Error('Invalid Private Key')
      }
    } else {
      throw new Error('Invalid Private Key')
    }
    let decrypted
    const AESopts = { mode: WalletCrypto.AES.ECB, padding: WalletCrypto.NoPadding }

    const verifyHashAndReturn = function () {
      const tmpkey = Bitcoin.ECPair.fromPrivateKey(decrypted, null, {
        compressed: isCompPoint,
        network
      })

      const base58Address = utils.btc.keyPairToAddress(tmpkey)

      checksum = hash256(base58Address)

      if (
        checksum[0] !== hex[3] ||
        checksum[1] !== hex[4] ||
        checksum[2] !== hex[5] ||
        checksum[3] !== hex[6]
      ) {
        throw new Error('wrong_bip38_pass')
      }
      return tmpkey
    }

    if (!isECMult) {
      const addresshash = Buffer.from(hex.slice(3, 7), 'hex')

      const derivedBytes = scrypt(passphrase, addresshash, 16384, 8, 8, 64)
      var k = derivedBytes.slice(32, 32 + 32)

      const decryptedBytes = WalletCrypto.AES.decrypt(
        Buffer.from(hex.slice(7, 7 + 32), 'hex'),
        k,
        null,
        AESopts
      )
      for (let x = 0; x < 32; x++) {
        decryptedBytes[x] ^= derivedBytes[x]
      }
      decrypted = decryptedBytes

      return verifyHashAndReturn()
    }
    const ownerentropy = hex.slice(7, 7 + 8)
    const ownersalt = Buffer.from(!hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4), 'hex')

    const prefactorA = scrypt(passphrase, ownersalt, 16384, 8, 8, 32)
    let passfactor

    if (!hasLotSeq) {
      passfactor = prefactorA
    } else {
      const prefactorB = Buffer.concat([prefactorA, Buffer.from(ownerentropy, 'hex')])
      passfactor = hash256(prefactorB)
    }

    const passpoint = Bitcoin.ECPair.fromPrivateKey(passfactor).publicKey

    const encryptedpart2 = Buffer.from(hex.slice(23, 23 + 16), 'hex')

    const addresshashplusownerentropy = Buffer.from(hex.slice(3, 3 + 12), 'hex')

    const derived = scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64)
    k = derived.slice(32)

    const unencryptedpart2Bytes = WalletCrypto.AES.decrypt(encryptedpart2, k, null, AESopts)

    for (let i = 0; i < 16; i++) {
      unencryptedpart2Bytes[i] ^= derived[i + 16]
    }

    const encryptedpart1 = Buffer.concat([
      Buffer.from(hex.slice(15, 15 + 8), 'hex'),
      Buffer.from(unencryptedpart2Bytes.slice(0, 0 + 8), 'hex')
    ])

    const unencryptedpart1Bytes = WalletCrypto.AES.decrypt(encryptedpart1, k, null, AESopts)

    for (let ii = 0; ii < 16; ii++) {
      unencryptedpart1Bytes[ii] ^= derived[ii]
    }

    const seedb = Buffer.concat([
      Buffer.from(unencryptedpart1Bytes.slice(0, 0 + 16), 'hex'),
      Buffer.from(unencryptedpart2Bytes.slice(8, 8 + 8), 'hex')
    ])

    const factorb = hash256(seedb)

    // secp256k1: N
    const N = BigInteger.fromHex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

    decrypted = BigInteger.fromBuffer(passfactor)
      .multiply(BigInteger.fromBuffer(factorb))
      .remainder(N)

    return verifyHashAndReturn()
  })  address: string
  change: boolean
  index: number
  path: string
  priv: string
  script: string
  txHash: string
  value: number
  xpub: string
}

export interface ISelection {
  fee: number
  inputs: ICoinSelectionCoinIO[]
  outputs: ICoinSelectionCoinIO[]
}import * as WalletCrypto from './utils'

const {
  crypto: { hash256 }
} = Bitcoin

export const parseBIP38toECPair = function (base58Encrypted, passphrase, network) {
  import('unorm').then((Unorm) => {
    let hex

    // Unicode NFC normalization
    passphrase = Unorm.nfc(passphrase)

    try {
      hex = Base58.decode(base58Encrypted)
    } catch (e) {
      throw new Error('Invalid Private Key')
    }

    if (hex.length !== 43) {
      throw new Error('Invalid Private Key')
    } else if (hex[0] !== 0x01) {
      throw new Error('Invalid Private Key')
    }

    const expChecksum = hex.slice(-4)
    hex = hex.slice(0, -4)

    let checksum = hash256(hex)

    if (
      checksum[0] !== expChecksum[0] ||
      checksum[1] !== expChecksum[1] ||
      checksum[2] !== expChecksum[2] ||
      checksum[3] !== expChecksum[3]
    ) {
      throw new Error('Invalid Private Key')
    }

    let isCompPoint = false
    let isECMult = false
    let hasLotSeq = false
    if (hex[1] === 0x42) {
      if (hex[2] === 0xe0) {
        isCompPoint = true
      } else if (hex[2] !== 0xc0) {
        throw new Error('Invalid Private Key')
      }
    } else if (hex[1] === 0x43) {
      isECMult = true
      isCompPoint = (hex[2] & 0x20) !== 0
      hasLotSeq = (hex[2] & 0x04) !== 0
      if ((hex[2] & 0x24) !== hex[2]) {
        throw new Error('Invalid Private Key')
      }
    } else {
      throw new Error('Invalid Private Key')
    }
    let decrypted
    const AESopts = { mode: WalletCrypto.AES.ECB, padding: WalletCrypto.NoPadding }

    const verifyHashAndReturn = function () {
      const tmpkey = Bitcoin.ECPair.fromPrivateKey(decrypted, null, {
        compressed: isCompPoint,
        network
      })

      const base58Address = utils.btc.keyPairToAddress(tmpkey)

      checksum = hash256(base58Address)

      if (
        checksum[0] !== hex[3] ||
        checksum[1] !== hex[4] ||
        checksum[2] !== hex[5] ||
        checksum[3] !== hex[6]
      ) {
        throw new Error('wrong_bip38_pass')
      }
      return tmpkey
    }

    if (!isECMult) {
      const addresshash = Buffer.from(hex.slice(3, 7), 'hex')

      const derivedBytes = scrypt(passphrase, addresshash, 16384, 8, 8, 64)
      var k = derivedBytes.slice(32, 32 + 32)

      const decryptedBytes = WalletCrypto.AES.decrypt(
        Buffer.from(hex.slice(7, 7 + 32), 'hex'),
        k,
        null,
        AESopts
      )
      for (let x = 0; x < 32; x++) {
        decryptedBytes[x] ^= derivedBytes[x]
      }
      decrypted = decryptedBytes

      return verifyHashAndReturn()
    }
    const ownerentropy = hex.slice(7, 7 + 8)
    const ownersalt = Buffer.from(!hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4), 'hex')

    const prefactorA = scrypt(passphrase, ownersalt, 16384, 8, 8, 32)
    let passfactor

    if (!hasLotSeq) {
      passfactor = prefactorA
    } else {
      const prefactorB = Buffer.concat([prefactorA, Buffer.from(ownerentropy, 'hex')])
      passfactor = hash256(prefactorB)
    }

    const passpoint = Bitcoin.ECPair.fromPrivateKey(passfactor).publicKey

    const encryptedpart2 = Buffer.from(hex.slice(23, 23 + 16), 'hex')

    const addresshashplusownerentropy = Buffer.from(hex.slice(3, 3 + 12), 'hex')

    const derived = scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64)
    k = derived.slice(32)

    const unencryptedpart2Bytes = WalletCrypto.AES.decrypt(encryptedpart2, k, null, AESopts)

    for (let i = 0; i < 16; i++) {
      unencryptedpart2Bytes[i] ^= derived[i + 16]
    }

    const encryptedpart1 = Buffer.concat([
      Buffer.from(hex.slice(15, 15 + 8), 'hex'),
      Buffer.from(unencryptedpart2Bytes.slice(0, 0 + 8), 'hex')
    ])

    const unencryptedpart1Bytes = WalletCrypto.AES.decrypt(encryptedpart1, k, null, AESopts)

    for (let ii = 0; ii < 16; ii++) {
      unencryptedpart1Bytes[ii] ^= derived[ii]
    }

    const seedb = Buffer.concat([
      Buffer.from(unencryptedpart1Bytes.slice(0, 0 + 16), 'hex'),
      Buffer.from(unencryptedpart2Bytes.slice(8, 8 + 8), 'hex')
    ])

    const factorb = hash256(seedb)

    // secp256k1: N
    const N = BigInteger.fromHex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')

    decrypted = BigInteger.fromBuffer(passfactor)
      .multiply(BigInteger.fromBuffer(factorb))
      .remainder(N)

    return verifyHashAnimport memoize from 'fast-memoize'
import shuffle from 'fisher-yates'
import { List } from 'immutable-ext'
import {
  clamp,
  curry,
  filter,
  head,
  is,
  isEmpty,
  isNil,
  last,
  map,
  reduce,
  sort,
  tail,
  unfold
} from 'ramda'
import seedrandom from 'seedrandom'

import * as Coin from './coin.js'

// getByteCount implementation
// based on https://gist.github.com/junderw/b43af3253ea5865ed52cb51c200ac19c
// Usage:
// - getByteCount({'P2WPKH':45},{'P2PKH':1}) Means "45 inputs of P2WPKH and 1 output of P2PKH"
// - getByteCount({'P2PKH':1,'P2WPKH':2},{'P2PKH':2}) means "1 P2PKH input and 2 P2WPKH inputs along with 2 P2PKH outputs"

// assumes compressed pubkeys in all cases.
// TODO: SEGWIT  we need to account for uncompressed pubkeys!
export const IO_TYPES = {
  inputs: {
    P2PKH: 148, // legacy
    P2WPKH: 67.75 // native segwit
  },
  outputs: {
    P2PKH: 34,
    P2SH: 32,
    P2WPKH: 31,
    P2WSH: 43
  }
}
const VBYTES_PER_WEIGHT_UNIT = 4

// isFromAccount :: selection -> boolean
export const isFromAccount = (selection) =>
  selection.inputs[0] ? selection.inputs[0].isFromAccount() : false

// isFromLegacy :: selection -> boolean
export const isFromLegacy = (selection) =>
  selection.inputs[0] ? selection.inputs[0].isFromLegacy() : false

export const dustThreshold = (feeRate, change) =>
  Math.ceil((Coin.inputBytes(change) + Coin.outputBytes(change)) * feeRate)

export const getByteCount = (inputs, outputs) => {
  let vBytesTotal = 0
  let hasWitness = false
  let inputCount = 0
  let outputCount = 0
  // assumes compressed pubkeys in all cases.

  function checkUInt53(n) {
    if (n < 0 || n > Number.MAX_SAFE_INTEGER || n % 1 !== 0)
      throw new RangeError('value out of range')
  }

  function varIntLength(number) {
    checkUInt53(number)

    return number < 0xfd ? 1 : number <= 0xffff ? 3 : number <= 0xffffffff ? 5 : 9
  }

  Object.keys(inputs).forEach(function (key) {
    checkUInt53(inputs[key])
    vBytesTotal += IO_TYPES.inputs[key] * inputs[key]
    inputCount += inputs[key]
    if (key.indexOf('W') >= 0) hasWitness = true
  })

  Object.keys(outputs).forEach(function (key) {
    checkUInt53(outputs[key])
    vBytesTotal += IO_TYPES.outputs[key] * outputs[key]
    outputCount += outputs[key]
  })

  // segwit marker + segwit flag + witness element count
  let overhead = hasWitness ? 0.25 + 0.25 + varIntLength(inputCount) / VBYTES_PER_WEIGHT_UNIT : 0

  overhead += 4 // nVersion
  overhead += varIntLength(inputCount)
  overhead += varIntLength(outputCount)
  overhead += 4 // nLockTime

  vBytesTotal += overhead
  return vBytesTotal
}

export const transactionBytes = (inputs, outputs) => {
  const coinTypeReducer = (acc, coin) => {
    const type = coin.type ? coin.type() : 'P2PKH'
    if (acc[type]) acc[type] += 1
    else acc[type] = 1
    return acc
  }

  const inputTypeCollection = reduce(coinTypeReducer, {}, inputs)
  const outputTypeCollection = reduce(coinTypeReducer, {}, outputs)
  return getByteCount(inputTypeCollection, outputTypeCollection)
}

export const changeBytes = (type) => IO_TYPES.outputs[type]

export const effectiveBalance = curry((feePerByte, inputs, outputs = [{}]) =>
  List(inputs)
    .fold(Coin.empty)
    .overValue((v) =>
      clamp(0, Infinity, v - Math.ceil(transactionBytes(inputs, outputs) * feePerByte))
    )
)

// findTarget :: [Coin(x), ..., Coin(y)] -> Number -> [Coin(a), ..., Coin(b)] -> Selection
const ft = (targets, feePerByte, coins, changeAddress) => {
  const target = List(targets).fold(Coin.empty).value
  const _findTarget = (seed) => {
    const accValue = seed[0]
    const accFee = seed[1]
    const newCoin = head(seed[2])
    if (isNil(newCoin) || accValue >= target + accFee) {
      return false
    }
    const partialFee = accFee + Coin.inputBytes(newCoin) * feePerByte
    const restCoins = tail(seed[2])
    const nextAcc = accValue + newCoin.value
    return [
      [nextAcc, partialFee, newCoin],
      [nextAcc, partialFee, restCoins]
    ]
  }
  const partialFee = Math.ceil(transactionBytes([], targets) * feePerByte)
  const effectiveCoins = filter((c) => Coin.effectiveValue(feePerByte, c) > 0, coins)
  const selection = unfold(_findTarget, [0, partialFee, effectiveCoins])
  if (isEmpty(selection)) {
    // no coins to select
    return { fee: 0, inputs: [], outputs: [] }
  }
  const maxBalance = last(selection)[0]
  const fee = last(selection)[1]
  const selectedCoins = map((e) => e[2], selection)
  if (maxBalance < target + fee) {
    // not enough money to satisfy target
    return { fee, inputs: [], outputs: targets }
  }
  // Value remaining after deducting the 'target' value and fees.
  const remainingValue = maxBalance - target - fee
  // A Coin with the full remaining value and the change address.
  const proposedChangeCoin = Coin.fromJS({
    address: changeAddress,
    change: true,
    value: remainingValue
  })
  // Check if we should keep change.
  if (remainingValue >= dustThreshold(feePerByte, proposedChangeCoin)) {
    // Change is worth keeping
    const feeForAdditionalChangeOutput = changeBytes(proposedChangeCoin.type()) * feePerByte
    // Create the final change Coin, its value is the remainingValue minus
    // the fee it takes to have it added to the transaction.
    const changeCoin = Coin.fromJS({
      address: changeAddress,
      change: true,
      value: remainingValue - feeForAdditionalChangeOutput
    })
    return {
      fee: fee + feeForAdditionalChangeOutput,
      inputs: selectedCoins,
      outputs: [...targets, changeCoin]
    }
  }
  // Change is not worth keeping, burn change
  return { fee: fee + remainingValue, inputs: selectedCoins, outputs: targets }
}
export const findTarget = memoize(ft)

// singleRandomDraw :: Number -> [Coin(a), ..., Coin(b)] -> String -> Selection
export const selectAll = (feePerByte, coins, outAddress) => {
  const effectiveCoins = filter((c) => Coin.effectiveValue(feePerByte, c) > 0, coins)
  const effBalance = effectiveBalance(feePerByte, effectiveCoins).value
  const Balance = List(effectiveCoins).fold(Coin.empty).value
  const fee = Balance - effBalance
  return {
    fee,
    inputs: effectiveCoins,
    outputs: [Coin.fromJS({ address: outAddress, value: effBalance })]
  }
}
// singleRandomDraw :: [Coin(x), ..., Coin(y)] -> Number -> [Coin(a), ..., Coin(b)] -> String -> Selection
export const singleRandomDraw = (targets, feePerByte, coins, changeAddress, seed) => {
  const rng = is(String, seed) ? seedrandom(seed) : undefined
  return findTarget(targets, feePerByte, shuffle(coins, rng), changeAddress)
}

// descentDraw :: [Coin(x), ..., Coin(y)] -> Number -> [Coin(a), ..., Coin(b)] -> Selection
export const descentDraw = (targets, feePerByte, coins, changeAddress) =>
  findTarget(
    targets,
    feePerByte,
    sort((a, b) => a.descentCompareWeighted(b), coins),
    changeAddress
  )

// ascentDraw :: [Coin(x), ..., Coin(y)] -> Number -> [Coin(a), ..., Coin(b)] -> Selection
export const ascentDraw = (targets, feePerByte, coins, changeAddress) =>
  findTarget(
    targets,
    feePerByte,    expect(bip69SortOutputs(assortedOutputs)).toEqual(sortedOutputs){
  "name": "blockchain-wallet-v4",
  "version": "1.0.1",
  "description": "Functional library for handling Blockchain.com wallets.",
  "license": "AGPL-3.0-or-later",
  "author": {
    "name": "Blockchain",
    "url": "https://blockchain.com"
  },
  "main": "lib/index.js",
  "module": "src/index.js",
  "scripts": {
    "ci:test": "yarn test --runInBand",
    "clean": "cross-env rimraf node_modules && rimraf lib",
    "compile": "npx babel -d lib/ --ignore spec.js src/ --copy-files",
    "coverage": "cross-env npx jest --coverage",
    "link:resolved:paths": "ln -sf $(pwd)/src/** ./node_modules && ln -sf $(pwd)/../../packages/blockchain-wallet-v4-frontend ./node_modules",
    "test": "cross-env npx jest --runInBand",
    "test:build": "yarn compile",
    "test:debug": "cross-env npx --inspect-brk jest --runInBand",
    "test:watch": "cross-env npx jest --watchAll --runInBand"
  },
  "jest": {
    "collectCoverageFrom": [
      "src/**/*.{js,ts}",
      "!src/exchange/currencies/*.js",
      "!src/network/*.{js,ts}",
      "!src/network/api/**/*.{js,ts}",
      "!src/redux/**/**/sagas.{js,ts}",
      "!src/redux/**/**/sagaRegister.{js,ts}",
      "!src/redux/*.{js,ts}"
    ],
    "coverageDirectory": "<rootDir>/../../coverage/blockchain-wallet-v4",
    "coverageReporters": [
      "json",
      "html"
    ],
    "modulePathIgnorePatterns": [
      "<rootDir>/lib"
    ],
    "moduleNameMapper": {
      "@core(.*)$": "<rootDir>/src/$1"
    },
    "setupFiles": [
      "<rootDir>/../../config/jest/jest.shim.js",
      "<rootDir>/../../config/jest/jest.config.js"
    ],
    "testPathIgnorePatterns": [
      "<rootDir>/lib"
    ],
    "transform": {
      "^.+\\.jsx?$": "babel-jest",
      "^.+\\.tsx?$": "ts-jest"
    },
    "testEnvironment": "jsdom"
  },
  "dependencies": {
    "@opensea/seaport-js": "1.0.2",
    "axios": "0.21.4",
    "bech32": "1.1.3",
    "big-rational": "0.10.9",
    "bigi": "1.4.2",
    "bignumber.js": "8.0.2",
    "bip32": "2.0.6",
    "bip32-path": "0.4.2",
    "bip39-light": "1.0.7",
    "bip69": "2.1.4",
    "bitcoinforksjs-lib": "https://github.com/blockchain/bitcoinjs-lib.git#opt-in-bitcoincash-sighash",
    "bitcoinjs-lib": "5.2.0",
    "bitcoinjs-message": "2.2.0",
    "bs58": "4.0.1",
    "cashaddress": "1.1.0",
    "daggy": "1.4.0",
    "data.either": "1.5.2",
    "data.maybe": "1.2.3",
    "data.task": "3.1.2",
    "date-fns": "2.28.0",
    "ed25519-hd-key": "1.2.0",
    "es6-promise": "4.2.8",
    "ethereumjs-tx": "1.3.7",
    "ethers": "5.6.7",
    "extendable-immutable": "1.3.3",
    "fast-memoize": "2.5.2",
    "firebase": "9.17.1",
    "fisher-yates": "1.0.3",
    "futurize": "1.2.0",
    "immutable": "3.8.1",
    "immutable-ext": "1.1.5",
    "isomorphic-fetch": "2.2.1",
    "pbkdf2": "3.1.2",
    "query-string": "7.0.0",
    "ramda": "0.26.1",
    "ramda-lens": "git+https://github.com/ramda/ramda-lens.git",
    "read-blob": "1.1.2",
    "redux": "4.0.5",
    "redux-immutable": "4.0.0",
    "redux-saga": "1.1.3",
    "reselect": "4.0.0",
    "scrypt-js": "3.0.1",
    "seedrandom": "2.4.3",
    "stellar-sdk": "8.2.5",
    "unorm": "1.6.0",
    "uuid": "8.3.2"
  }
}import { List } from 'immutable-ext'
import { map } from 'ramda'

import * as Coin from './coin.js'

describe('Coin Selection', () => {
  describe('Coin Type', () => {
    it('coins monoid both valued', () => {
      const A = Coin.fromJS({ value: 100 })
      const B = Coin.fromJS({ value: 300 })
      expect(A.concat(B).value).toEqual(400)
    })
    it('coins monoid one valued', () => {
      const coins = map(Coin.fromJS, [
        { value: 1 },
        { value: 2 },
        { value: 3 },
        { value: 4 },
        { value: 5 },
        { value: 6 },
        { value: 7 },
        { value: 8 },
        { value: 9 },
        { value: 10 }
      ])
      const sum = List(coins).fold(Coin.empty).value
      expect(sum).toEqual(55)
    })
    it('coins setoid both valued', () => {
      const A = Coin.fromJS({ value: 100 })
      const B = Coin.fromJS({ value: 100 })
      expect(A.equals(B)).toEqual(true)
    })
    it('coins setoid one valued', () => {
      const A = Coin.fromJS({ value: 100 })
      const B = Coin.fromJS({ value: 0 })
      expect(A.equals(B)).toEqual(false)
      expect(A.lte(B)).toEqual(false)
    })
    it('coins setoid one valued lte', () => {
      const A = Coin.fromJS({ value: 0 })
      const B = Coin.fromJS({ value: 100 })
      expect(A.lte(B)).toEqual(true)
    })
    it('coins map', () => {
      const A = Coin.fromJS({ value: 100 })
      const square = (x) => x * x
      expect(A.overValue(square).value).toEqual(square(A.value))
    })
    it('coin empty', () => {
      const A = Coin.empty
      expect(A.value).toEqual(0)
    })
  })
  describe('coin byte sizes', () => {
    it('should return the right IO sizes for P2PKH', () => {
      expect(Coin.inputBytes({})).toEqual(148)
      expect(Coin.outputBytes({})).toEqual(34)
    })
    it('should return the right IO sizes for P2WPKH', () => {
      expect(Coin.inputBytes({ type: () => 'P2WPKH' })).toEqual(67.75)
      expect(Coin.outputBytes({ type: () => 'P2WPKH' })).toEqual(31)
    })
  })
  describe('effective values', () => {
    // value - feePerByte * input size
    it('should return the right coin value', () => {
      const A = Coin.fromJS({ value: 15000 })
      expect(Coin.effectiveValue(55, A)).toEqual(6860) // 15000 - 55 * 148 = 6860

      const B = Coin.fromJS({
        address: 'bc1qxddx2wmn97swgznpkthv940ktg8ycxg0ygxxp9',
        value: 15000
      })
      expect(Coin.effectiveValue(55, B)).toEqual(11274) // 15000 - 55 * 67.75 = 11273.75
    })
    it('should return zero coin value', () => {
      expect(Coin.effectiveValue(55000, Coin.fromJS({ value: 15000 }))).toEqual(0)
    })
    it('should return max coin value', () => {
      expect(Coin.effectiveValue(0, Coin.fromJS({ value: 15000 }))).toEqual(15000)
    })
  })
})

describe('bip69SortInputs', () => {
  const { bip69SortInputs } = Coin
  it('should sort inputs by hash', () => {
    const assortedInputs = [
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 1
      },
      {
        txHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        value: 2
      },
      {
        txHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        value: 3
      },
      {
        txHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbff',
        value: 4
      },
      {
        txHash: 'ffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        value: 5
      }
    ].map((input) => new Coin.Coin(input))
    const sortedInputs = [
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 1
      },
      {
        txHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        value: 3
      },
      {
        txHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbff',
        value: 4
      },
      {
        txHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        value: 2
      },
      {
        txHash: 'ffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        value: 5
      }
    ].map((input) => new Coin.Coin(input))
    expect(bip69SortInputs(assortedInputs)).toEqual(sortedInputs)
  })

  it('should sort inputs with equal hash by value', () => {
    const assortedInputs = [
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 1
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 0
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 3
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 10
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 2
      }
    ].map((input) => new Coin.Coin(input))
    const sortedInputs = [
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 0
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 1
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 2
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 3
      },
      {
        txHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        value: 10
      }
    ].map((input) => new Coin.Coin(input))
    expect(bip69SortInputs(assortedInputs)).toEqual(sortedInputs)
  })
})

describe('bip69SortOutputs', () => {
  const { bip69SortOutputs } = Coin
  it('should sort ouputs by value', () => {
    const assortedOutputs = [
      {
        script: '00000000',
        value: 1
      },
      {
        script: '11111111',
        value: 0
      },
      {
        script: '00000000',
        value: 3
      },
      {
        script: '11111111',
        value: 10
      },
      {
        script: '22222222',
        value: 2
      }
    ].map(
      (output) =>
        new Coin.Coin({
          ...output,
          script: Buffer.from(output.script, 'hex')
        })
    )
    const sortedOutputs = [
      {
        script: '11111111',
        value: 0
      },
      {
        script: '00000000',
        value: 1
      },
      {
        script: '22222222',
        value: 2
      },
      {
        script: '00000000',
        value: 3
      },
      {
        script: '11111111',
        value: 10
      }
    ].map(
      (output) =>
        new Coin.Coin({
          ...output,
          script: Buffer.from(output.script, 'hex')
        })
    )
    expect(bip69SortOutputs(assortedOutputs)).toEqual(sortedOutputs)
  })

  it('should sort outups with equal value by script', () => {
    const assortedOutputs = [
      {
        script: '00000000',
        value: 0
      },
      {
        script: '11111111',
        value: 0
      },
      {
        script: '00000000',
        value: 0
      },
      {
        script: '11111111',
        value: 0
      },
      {
        script: '22222222',
        value: 0
      }
    ].map(
      (output) =>
        new Coin.Coin({
          ...output,
          script: Buffer.from(output.script, 'hex')
        })
    )
    const sortedOutputs = [
      {
        script: '00000000',
        value: 0
      },
      {
        script: '00000000',
        value: 0
      },
      {
        script: '11111111',
        value: 0
      },
      {
        script: '11111111',
        value: 0
      },
      {
        script: '22222222',
        value: 0
      }
    ].map(
      (output) =>
        new Coin.Coin({
          ...output,
          script: Buffer.from(output.script, 'hex')
        })
    )
    expect(bip69SortOutputs(assortedOutputs)).toEqual(sortedOutputs)
  })
    sort((a, b) => a.ascentCompareWeighted(b), coins),
    changeAddress
  )dReturn()
  })
}
