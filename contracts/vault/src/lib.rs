//! # Callora Vault Contract
//!
//! ## Access Control
//!
//! The vault implements role-based access control for deposits:
//!
//! - **Owner**: Set at initialization, immutable via `transfer_ownership`. Always permitted to deposit.
//! - **Allowed Depositors**: Optional addresses (e.g., backend service) that can be
//!   explicitly approved by the owner. Can be set, changed, or cleared at any time.
//! - **Other addresses**: Rejected with an authorization error.
//!
//! ### Production Usage
//!
//! In production, the owner typically represents the end user's account, while the
//! allowed depositors are backend services that handle automated deposits on behalf
//! of the user.
//!
//! ### Managing the Allowed Depositors
//!
//! - Add: `set_allowed_depositor(Some(address))` – adds the address if not already present.
//! - Clear: `set_allowed_depositor(None)` – revokes all depositor access.
//! - Only the owner may call `set_allowed_depositor`.
//!
//! ### Security Model
//!
//! - The owner has full control over who can deposit.
//! - Allowed depositors are trusted addresses (typically backend services).
//! - Access can be revoked at any time by the owner.
//! - All deposit attempts are authenticated against the caller's address.
//!
//! ## Pause / Circuit Breaker
//!
//! The vault exposes an emergency pause mechanism that lets the **Admin** or **Owner**
//! halt sensitive write operations without losing funds:
//!
//! - **Blocked while paused**: `deposit`, `deduct`, `batch_deduct`.
//! - **Allowed while paused**: `withdraw`, `withdraw_to`, `distribute` — these are
//!   recovery paths that must remain available so the owner can always reclaim funds
//!   during an incident.
//!
//! Toggle functions:
//! - `pause(caller)`   – blocks sensitive operations; emits `vault_paused`.
//! - `unpause(caller)` – restores normal operation; emits `vault_unpaused`.
//! - `is_paused()`     – read-only state query; returns `false` before first `pause` call.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, String, Symbol, Vec};

/// Single item for batch deduct: amount and optional request id for idempotency/tracking.
#[contracttype]
#[derive(Clone)]
pub struct DeductItem {
    pub amount: i128,
    pub request_id: Option<Symbol>,
}

/// Vault metadata stored on-chain.
#[contracttype]
#[derive(Clone)]
pub struct VaultMeta {
    pub owner: Address,
    pub balance: i128,
    pub authorized_caller: Option<Address>,
    pub min_deposit: i128,
}

/// Unified storage key enum for all vault contract state.
///
/// All instance storage access MUST go through this enum to prevent key collisions
/// and ensure type-safe, auditable storage access patterns.
#[contracttype]
pub enum DataKey {
    /// Stores the primary vault metadata (`VaultMeta`): owner, balance, authorized_caller, min_deposit.
    Meta,
    /// Stores the list of allowed depositor addresses (`Vec<Address>`).
    /// Vec maintains stable insertion order. Present only when at least one depositor is set.
    AllowedDepositors,
    /// Stores the global admin `Address` (set to owner at init; transferable via `set_admin`).
    Admin,
    /// Stores the USDC token contract `Address` used for all token transfers.
    UsdcToken,
    /// Stores the optional settlement contract `Address`. When set, deduct transfers USDC here.
    Settlement,
    /// Stores the optional revenue pool `Address`. Used as fallback when no settlement is set.
    RevenuePool,
    /// Stores the maximum single-deduct cap (`i128`). Defaults to `i128::MAX` (no cap).
    MaxDeduct,
    Paused,
    Metadata(String),
    Paused,
    PendingOwner,
    PendingAdmin,
    DepositorList,
}

/// Default maximum single deduct amount when not set at init (no cap).
pub const DEFAULT_MAX_DEDUCT: i128 = i128::MAX;
/// Maximum number of items allowed in a single batch_deduct call.
pub const MAX_BATCH_SIZE: u32 = 50;

/// Maximum batch size for batch_deduct operations.
pub const MAX_BATCH_SIZE: u32 = 50;

/// Storage key for allowed depositors list.
pub const ALLOWED_KEY: &str = "allowed_depositors";

/// Maximum number of items allowed in a single batch_deduct call.
pub const MAX_BATCH_SIZE: u32 = 50;

/// Maximum length for offering metadata (e.g. IPFS CID or URI).
pub const MAX_METADATA_LEN: u32 = 256;
/// Maximum length for offering IDs.
pub const MAX_OFFERING_ID_LEN: u32 = 64;

#[contract]
pub struct CalloraVault;

#[contractimpl]
impl CalloraVault {
    /// Initialize vault for an owner with optional initial balance.
    /// Emits an "init" event with the owner address and initial balance.
    ///
    /// # Arguments
    /// * `owner`           – Vault owner; must authorize this call. Always permitted to deposit.
    /// * `usdc_token`      – Address of the USDC token contract.
    /// * `initial_balance` – Optional initial tracked balance (USDC must already be in the contract).
    /// * `min_default `0`).
    /// * `revenue_pool`    – Optional address to receive USDC on each deduct. If `None`, USDC stays in vault.
    /// * `max_deduct`      – Optional cap per single deduct; if `None`, uses `DEFAULT_MAX_DEDUCT` (no cap).
    ///
    /// # Panics
    /// * `"vault already initialized"` – if called more than once.
    /// * `"initial balance must be non-negative"` – if `initial_balance` is negative.
    ///
    /// # Events
    /// Emits topic `("init", owner)` with data `balance` on success.
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        env: Env,
        owner: Address,
        usdc_token: Address,
        initial_balance: Option<i128>,
        authorized_caller: Option<Address>,
        min_deposit: Option<i128>,
        revenue_pool: Option<Address>,
        max_deduct: Option<i128>,
    ) -> VaultMeta {
        owner.require_auth();
        let inst = env.storage().instance();
        if inst.has(&DataKey::Meta) {
            panic!("vault already initialized");
        }

        // Validate token and revenue pool are not the vault itself
        assert!(
            usdc_token != env.current_contract_address(),
            "usdc_token cannot be vault address"
        );
        if let Some(pool) = &revenue_pool {
            assert!(
                pool != &env.current_contract_address(),
                "revenue_pool cannot be vault address"
            );
        }

        let balance = initial_balance.unwrap_or(0);
        assert!(balance >= 0, "initial balance must be non-negative");

        let min_deposit_val = min_deposit.unwrap_or(0);
        assert!(min_deposit_val >= 0, "min_deposit must be non-negative");

        let max_deduct_val = max_deduct.unwrap_or(DEFAULT_MAX_DEDUCT);
        assert!(max_deduct_val > 0, "max_deduct must be positive");
        assert!(
            min_deposit_val <= max_deduct_val,
            "min_deposit cannot exceed max_deduct"
        );

        let meta = VaultMeta {
            owner: owner.clone(),
            balance,
            authorized_caller,
            min_deposit: min_deposit_val,
        };

        inst.set(&DataKey::Meta, &meta);
        inst.set(&DataKey::UsdcToken, &usdc_token);
        insttaKey::Admin, &owner);
        if let Some(pool) = revenue_pool {
            inst.set(&DataKey::RevenuePool, &pool);
        }
        inst.set(&DataKey::MaxDeduct, &max_deduct_val);

        env.events()
            .publish((Symbol::new(&env, "init"), owner.clone()), balance);
        meta
    }

    /// Check if the caller is authorized to deposit (owner or allowed depositor).
    pub fn is_authorized_depositor(env: Env, caller: Address) -> bool {
        let meta = Self::get_meta(env.clone());
        if caller == meta.owner {
            return true;
        }

        let allowed: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::AllowedDepositors)
            .unwrap_or(Vec::new(&env));
        allowed.contains(&caller)
    }

    /// Return the current admin address.
    ///
    /// # Panics
    /// * `"vault not initialized"` – if called before `init`.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("vault not initialized")
    }

    /// Nominates a new administrative address.
    /// The nominee must call `accept_admin` to finalize the transfer.
    /// Can only be called by the current Admin.
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) {
        caller.require_auth();
        let current_admin = Self::get_admin(env.clone());
        if caller != current_admin {
            panic!("unauthorized: caller is not admin");
        }
        env.storage()
            .instance()
            .set(&StorageKey::PendingAdmin, &new_admin);

        env.events().publish(
            (
                Symbol::new(&env, "admin_nominated"),
                current_admin,
                new_admin,
            ),
            (),
        );
    }

    /// Accepts the administrative role.
    /// Can only be called by the pending Admin.
    pub fn accept_admin(env: Env) {
        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&StorageKey::PendingAdmin)
            .expect("no admin transfer pending");
        pending_admin.require_auth();

        let current_admin = Self::get_admin(env.clone());
        env.storage()
            .instance()
            .set(&StorageKey::Admin, &pending_admin);
        env.storage().instance().remove(&StorageKey::PendingAdmin);

        env.events().publish(
            (
                Symbol::new(&env, "admin_accepted"),
                current_admin,
                pending_admin,
            ),
            (),
        );
    }

    /// Require that the caller is the owner, panic otherwise.
    pub fn require_owner(env: Env, caller: Address) {
        let meta = Self::get_meta(env.clone());
        assert!(caller == meta.owner, "unauthorized: owner only");
    }

    /// Distribute accumulated USDC to a single developer address.
    ///
    /// # Panics
    /// * `"unauthorized: caller is not admin"` – caller is not the admin.
    /// * `"amount must be positive"`           – amount is zero or negative.
    /// * `"insufficient USDC balance"`         – vault holds less than amount.
    ///
    /// # Events
    /// Emits topic `("distribute", to)` with data `amount` on success.
    pub fn distribute(env: Env, caller: Address, to: Address, amount: i128) {
        caller.require_auth();
        let admin = Self::get_admin(env.clone());
        if caller != admin {
            panic!("unauthorized: caller is not admin");
        }
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let usdc_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::UsdcToken)
            .expect("vault not initialized");
        let usdc = token::Client::new(&env, &usdc_address);
        let vault_balance = usdc.balance(&env.current_contract_address());
        if vault_balance < amount {
            panic!("insufficient USDC balance");
        }
        usdc.transfer(&env.current_contract_address(), &to, &amount);
        env.events()
            .publish(), amount);
    }

    /// Get vault metadata (owner, balance, and min_deposit).
    ///
    /// # Panics
    /// * `"vault not initialized"` – if called before `init`.
    pub fn get_meta(env: Env) -> VaultMeta {
        env.storage()
            .instance()
            .get(&DataKey::Meta)
            .unwrap_or_else(|| panic!("vault not initialized"))
    }

    /// Sets whether an address is allowed to deposit into the vault.
    /// Can only be called by the Owner.
    pub fn set_allowed_depositor(env: Env, caller: Address, depositor: Address) {
        caller.require_auth();
        Self::require_owner(env.clone(), caller);

        // Reject duplicate adds so integration bugs surface early.
        let mut list: Vec<Address> = env
            .storage()
            .instance()
            .get(&StorageKey::DepositorList)
            .unwrap_or(Vec::new(&env));

        assert!(!list.contains(&depositor), "already allowed");

        // Per-address flag for O(1) membership checks in `is_authorized_depositor`.
        env.storage()
            .instance()
            .set(&StorageKey::AllowedDepositors, &depositor); // kept for ABI compat
                                                              // Append to enumeration list.
        list.push_back(depositor);
        env.storage()
            .instance()
            .set(&StorageKey::DepositorList, &list);
    }

    /// Remove **all** addresses from the allowed-depositor allowlist.
    ///
    /// Safe to call on an already-empty list (no-op).
    /// Only the **owner** may call this.
    ///
    /// # Storage
    /// Removes `StorageKey::AllowedDepositors` and resets
    /// `StorageKey::DepositorList` to an empty vector.
    pub fn clear_allowed_depositors(env: Env, caller: Address) {
        caller.require_auth();
        Self::require_owner(env.clone(), caller);

        env.storage()
            .instance()
            .remove(&StorageKey::AllowedDepositors);
        env.storage()
            .instance()
            .set(&StorageKey::DepositorList, &Vec::<Address>::new(&env));
    }

    /// Return the full ordered list of currently allowed depositors.
    /// Suitable for off-chain auditing.
    pub fn get_allowed_depositors(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&StorageKey::DepositorList)
            .unwrap_or(Vec::new(&env))
    }

    /// Sets the authorized caller permitted to trigger deductions.
    /// Can only be called by the Owner.
    pub fn set_authorized_caller(env: Env, caller: Address) {
        let mut meta = Self::get_meta(env.clone());
        meta.owner.require_auth();

        meta.authorized_caller = Some(caller.clone());
        env.storage().instance().set(&DataKey::Meta, &meta);

        env.events().publish(
            (Symbol::new(&env,caller"), meta.owner.clone()),
            caller,
        );
    }

    /// Emergency pause — blocks `deposit`, `deduct`, and `batch_deduct`.
    ///
    /// Withdrawals (`withdraw`, `withdraw_to`) and `distribute` remain available
    /// so the owner can always recover funds during an incident.
    ///
    /// # Arguments
    /// * `caller` – Must be the vault Admin or Owner.
    ///
    /// # Panics
    /// * `"unauthorized: caller is not admin or owner"` – if caller is neither.
    /// * `"vault already paused"`                       – if already in paused state.
    ///
    /// # Events
    /// Emits topic `("vault_paused", caller)` with no data on success.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        Self::require_admin_or_owner(env.clone(), &caller);
        assert!(!Self::is_paused(env.clone()), "vault already paused");
        env.storage().instance().set(&StorageKey::Paused, &true);
        env.events()
            .publish((Symbol::new(&env, "vault_paused"), caller), ());
    }

    /// Emergency unpause — restores `deposit`, `deduct`, and `batch_deduct`.
    ///
    /// # Arguments
    /// * `caller` – Must be the vault Admin or Owner.
    ///
    /// # Panics
    /// * `"unauthorized: caller is not admin or owner"` – if caller is neither.
    /// * `"vault not paused"`                           – if not currently paused.
    ///
    /// # Events
    /// Emits topic `("vault_unpaused", caller)` with no data on success.
    pub fn unpause(env: Env, caller: Address) {
        caller.require_auth();
        Self::require_admin_or_owner(env.clone(), &caller);
        assert!(Self::is_paused(env.clone()), "vault not paused");
        env.storage().instance().set(&StorageKey::Paused, &false);
        env.events()
            .publish((Symbol::new(&env, "vault_unpaused"), caller), ());
    }

    /// Returns `true` if the vault is currently paused, `false` otherwise.
    ///
    /// Will return `false` before `pause` is ever called.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&StorageKey::Paused)
            .unwrap_or(false)
    }

    /// Deposits USDC into the vault.
    /// Can be called by the Owner or any Allowed Depositor.
    ///
    /// # Panics
    /// * `"vault is paused"` – if the circuit breaker is active.
    pub fn deposit(env: Env, caller: Address, amount: i128) -> i128 {
        caller.require_auth();
        Self::require_not_paused(env.clone());
        assert!(amount > 0, "amount must be positive");
        assert!(
            Self::is_authorized_depositor(env.clone(), caller.clone()),
            "unauthorized: only owner or allowed depositor can deposit"
        );

        let mut meta = Self::get_meta(env.clone());
        assert!(
            amount >= meta.min_deposit,
            "deposit below minimum: {} < {}",
            amount,
            meta.min_deposit
        );
        let usdc_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::UsdcToken)
            .expect("vault not initialized");
        let usdc = token::Client::new(&env, &usdc_address);
        usdc.transfer(&caller, &env.current_contract_address(), &amount);

        let mut meta = Self::get_meta(env.clone());
        meta.balance = meta
            .balance
            .checked_add(amount)
            .unwrap_or_else(|| panic!("balance overflow"));
        env.storage().instance().set(&StorageKey::Meta, &meta);

        env.events().publish(
            (Symbol::new(&env, "deposit"), caller.clone()),
            (amount, meta.balance),
        );
        meta.balance
    }

    /// Pause deposits to the vault.
    /// Can only be called by the Admin.
    pub fn pause(env: Env, caller: Address) {
        caller.require_auth();
        let admin = Self::get_admin(env.clone());
        if caller != admin {
            panic!("unauthorized: caller is not admin");
        }
        env.storage().instance().set(&StorageKey::Paused, &true);
        env.events()
            .publish((Symbol::new(&env, "pause"), admin), ());
    }

    /// Unpause deposits to the vault.
    /// Can only be called by the Admin.
    pub fn unpause(env: Env, caller: Address) {
        caller.require_auth();
        let admin = Self::get_admin(env.clone());
        if caller != admin {
            panic!("unauthorized: caller is not admin");
        }
        env.storage().instance().set(&StorageKey::Paused, &false);
        env.events()
            .publish((Symbol::new(&env, "unpause"), admin), ());
    }

    /// Check if the vault is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&StorageKey::Paused)
            .unwrap_or(false)
    }

    pub fn get_max_deduct(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::MaxDeduct)
            .unwrap_or(DEFAULT_MAX_DEDUCT)
    }

    /// Deducts USDC from the vault for settlement or revenue pool.
    /// Can be called by the Owner or the Authorized Caller.
    ///
    /// # Panics
    /// * `"vault is paused"` – if the circuit breaker is active.
    pub fn deduct(env: Env, caller: Address, amount: i128, request_id: Option<Symbol>) -> i128 {
        // ── 1. Require Soroban-level auth for the caller ──────────────────────
        caller.require_auth();
        Self::require_not_paused(env.clone());
        assert!(amount > 0, "amount must be positive");

        // ── 3. Enforce max_deduct cap ─────────────────────────────────────────
        let max_deduct = Self::get_max_deduct(env.clone());
        assert!(amount <= max_deduct, "deduct amount exceeds max_deduct");

        // Check authorization: must be either the authorized_caller if set, or the owner.
        let meta = Self::get_meta(env.clone());
        let authorized = match &meta.authorized_caller {
            Some(auth_caller) => caller == *auth_caller || caller == meta.owner,
            None => caller == meta.owner,
        };
        assert!(authorized, "unauthorized caller");

        // ── 6. Balance safety: explicit guard prevents underflow ──────────────
        assert!(meta.balance >= amount, "insufficient balance");
        let mut meta = Self::get_meta(env.clone());
        meta.balance = meta.balance.checked_sub(amount).unwrap();
        env.storage().instance().set(&StorageKey::Meta, &meta);
        let inst = env.storage().instance();
        if let Some(settlement) = inst.get::<StorageKey, Address>(&StorageKey::Settlement) {
            let usdc_token: Address = inst.get(&StorageKey::UsdcToken).unwrap();
            Self::transfer_funds(&env, &usdc_token, &settlement, amount);
        } else if let Some(revenue_pool) = inst.get::<StorageKey, Address>(&StorageKey::RevenuePool)
        {
            Self::transfer_to_settlement(env.clone(), amount);
        }

        // ── 9. Emit event ONLY after successful deduction ─────────────────────
        //    Schema: topics = ("deduct", caller, request_id | ""), data = (amount, new_balance)
        let rid = request_id.unwrap_or(Symbol::new(&env, ""));
        env.events()
            .publish((Symbol::new(&env, "deduct"), caller, rid), (amount, meta.balance));

        meta.balance
    }

    /// Atomically deducts multiple amounts from the vault.
    ///
    /// The entire batch is validated before any state is written. If any item
    /// fails validation the call panics and no balance change occurs.
    ///
    /// # Panics
    /// * `"batch too large"` – more than `MAX_BATCH_SIZE` items.
    /// * `"batch_deduct requires at least one item"` – empty batch.
    /// * `"unauthorized caller"` – caller is not owner or authorized_caller.
    /// * `"amount must be positive"` – any item amount ≤ 0.
    /// * `"deduct amount exceeds max_deduct"` – any item exceeds the per-item cap.
    /// * `"insufficient balance"` – cumulative deductions exceed current balance.
    pub fn batch_deduct(env: Env, caller: Address, items: Vec<DeductItem>) -> i128 {
        caller.require_auth();

        let n = items.len();
        assert!(n > 0, "batch_deduct requires at least one item");
        assert!(n <= MAX_BATCH_SIZE, "batch too large");

        let max_deduct = Self::get_max_deduct(env.clone());
        let mut meta = Self::get_meta(env.clone());

        let authorized = match &meta.authorized_caller {
            Some(auth_caller) => caller == *auth_caller || caller == meta.owner,
            None => caller == meta.owner,
        };
        assert!(authorized, "unauthorized caller");

        // ── Phase 1: validate the full batch, compute totals ────────────────
        let mut running = meta.balance;
        let mut total_amount: i128 = 0;
        for item in items.iter() {
            assert!(item.amount > 0, "amount must be positive");
            assert!(
                item.amount <= max_deduct,
                "deduct amount exceeds max_deduct"
            );
            assert!(running >= item.amount, "insufficient balance");
            running = running.checked_sub(item.amount).unwrap();
            total_amount = total_amount.checked_add(item.amount).unwrap();
        }

        // ── Phase 2: write state ─────────────────────────────────────────────
        meta.balance = running;
        env.storage().instance().set(&StorageKey::Meta, &meta);

        // ── Phase 3: emit one event per item ─────────────────────────────────
        // Walk from original balance down so each event shows the running total
        // after that item — same semantics as single deduct events.
        let mut event_balance = meta.balance.checked_add(total_amount).unwrap();
        for item in items.iter() {
            event_balance = event_balance.checked_sub(item.amount).unwrap();
            let rid = item.request_id.clone().unwrap_or(Symbol::new(&env, ""));
            env.events().publish(
                (Symbol::new(&env, "deduct"), caller.clone(), rid),
                (item.amount, event_balance),
            );
        }

        // ── Phase 4: external transfer ───────────────────────────────────────
        let inst = env.storage().instance();
        if let Some(settlement) = inst.get::<DataKey, Address>(&DataKey::Settlement) {
            let usdc_token: Address = inst.get(&DataKey::UsdcToken).unwrap();
            Self::transfer_funds(&env, &usdc_token, &settlement, total_amount);
        } else if let Some(revenue_pool) = inst.get::<StorageKey, Address>(&StorageKey::RevenuePool)
        {
            Self::transfer_to_settlement(env.clone(), total_amount);
        }

        meta.balance
    }

    /// Return current balance.
    pub fn balance(env: Env) -> i128 {
        Self::get_meta(env).balance
    }

    /// Nominates a new owner for the vault.
    /// The nominee must call `accept_ownership` to finalize the transfer.
    /// Can only be called by the current Owner.
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        let meta = Self::get_meta(env.clone());
        meta.owner.require_auth();
        assert!(
            new_owner != meta.owner,
            "new_owner must be different from current owner"
        );

        env.storage()
            .instance()
            .set(&StorageKey::PendingOwner, &new_owner);

        env.events().publish(
            (
                Symbol::new(&env, "ownership_nominated"),
                meta.owner,
                new_owner,
            ),
            (),
        );
    }

    /// Accepts ownership of the vault.
    /// Can only be called by the pending Owner.
    pub fn accept_ownership(env: Env) {
        let pending_owner: Address = env
            .storage()
            .instance()
            .get(&StorageKey::PendingOwner)
            .expect("no ownership transfer pending");
        pending_owner.require_auth();

        let mut meta = Self::get_meta(env.clone());
        let old_owner = meta.owner.clone();
        meta.owner = pending_owner;

        env.storage().instance().set(&StorageKey::Meta, &meta);
        env.storage().instance().remove(&StorageKey::PendingOwner);

        env.events().publish(
            (
                Symbol::new(&env, "ownership_accepted"),
                old_owner,
                meta.owner,
            ),
            (),
        );
    }

    /// Withdraws USDC from the vault to the owner.
    /// Can only be called by the Owner.
    pub fn withdraw(env
        let mut meta = Self::get_meta(env.clone());
        meta.owner.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(meta.balance >= amount, "insufficient balance");
        let usdc_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::UsdcToken)
            .expect("vault not initialized");
        let usdc = token::Client::new(&env, &usdc_address);
        usdc.transfer(&env.current_contract_address(), &meta.owner, &amount);
        meta.balance = meta.balance.checked_sub(amount).unwrap();
        env.storage().instance().set(&StorageKey::Meta, &meta);

        env.events().publish(
            (Symbol::new(&env, "withdraw"), meta.owner.clone()),
            (amount, meta.balance),
        );
        meta.balance
    }

    /// Withdraws USDC from the vault to a specific recipient.
    /// Can only be called by the Owner.
    pub fn withdraw_to(env: Env, to: Address, amount: i128) -> i128 {
        let mut meta = Self::get_meta(env.clone());
        meta.owner.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(meta.balance >= amount, "insufficient balance");
        let usdc_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::UsdcToken)
            .expect("vault not initialized");
        let usdc = token::Client::new(&env, &usdc_address);
        usdc.transfer(&env.current_contract_address(), &to, &amount);
        meta.balance = meta.balance.checked_sub(amount).unwrap();
        env.storage().instance().set(&StorageKey::Meta, &meta);

        env.events().publish(
            (Symbol::new(&env, "withdraw_to"), meta.owner.clone(), to),
            (amount, meta.balance),
        );
        meta.balance
    }

    /// Sets the revenue pool address that receives USDC on each deduct.
    ///
    /// Admin-only. Pass `None` to clear the revenue pool address.
    ///
    /// **Routing priority**: when a deduct occurs, `settlement` is tried first;
    /// `revenue_pool` is used only when `settlement` is **not** configured.
    /// If neither is set, USDC stays in the vault after the balance is reduced.
    ///
    /// Updating this address is atomic – no partial state is possible.
    ///
    /// # Panics
    /// * `"unauthorized: caller is not admin"` – caller is not the admin.
    ///
    /// # Events
    /// Emits topic `("set_revenue_pool", caller)` with data `address` on set,
    /// or `("clear_revenue_pool", caller)` with data `()` on clear.
    pub fn set_revenue_pool(env: Env, caller: Address, revenue_pool: Option<Address>) {
        caller.require_auth();
        let current_admin = Self::get_admin(env.clone());
        if caller != current_admin {
            panic!("unauthorized: caller is not admin");
        }
        match revenue_pool {
            Some(addr) => {
                env.storage()
                    .instance()
                    .set(&StorageKey::RevenuePool, &addr);
                env.events().publish(
                    (Symbol::new(&env, "set_revenue_pool"), caller),
                    addr,
                );
            }
            None => {
                env.storage()
                    .instance()
                    .remove(&StorageKey::RevenuePool);
                env.events().publish(
                    (Symbol::new(&env, "clear_revenue_pool"), caller),
                    (),
                );
            }
        }
    }

    /// Get the revenue pool address, or `None` if not configured.
    pub fn get_revenue_pool(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&StorageKey::RevenuePool)
    }

    /// Sets the settlement contract address.
    /// Can only be called by the Admin.
    pub fn set_settlement(env: Env, caller: Address, settlement_address: Address) {
        caller.require_auth();
        let current_admin = Self::get_admin(env.clone());
        if caller != current_admin {
            panic!("unauthorized: caller is not admin");
        }
        env.storage()
            .instance()
            .set(&DataKey::Settlement, &settlement_address);
    }

    /// Get the settlement contract address.
    ///
    /// # Panics
 has been configured.
    pub fn get_settlement(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Settlement)
            .unwrap_or_else(|| panic!("settlement address not set"))
    }

    /// Store offering metadata. Owner-only.
    ///
    /// # Panics
    /// * `"unauthorized: owner only"` – caller is not the vault owner.
    ///
    /// # Events
    /// Emits topic `("metadata_set", offering_id, caller)` with data `metadata`.
    pub fn set_metadata(
        env: Env,
        caller: Address,
        offering_id: String,
        metadata: String,
    ) -> String {
        caller.require_auth();
        Self::require_owner(env.clone(), caller.clone());

        assert!(
            offering_id.len() <= MAX_OFFERING_ID_LEN,
            "offering_id exceeds max length"
        );
        assert!(
            metadata.len() <= MAX_METADATA_LEN,
            "metadata exceeds max length"
        );

        env.storage()
            .instance()
            .set(&DataKey::Metadata(offering_id.clone()), &metadata);
        env.events().publish(
            (Symbol::new(&env, "metadata_set"), offering_id, caller),
            metadata.clone(),
        );
        metadata
    }

    /// Retrieve stored offering metadata. Returns `None` if not set.
    pub fn get_metadata(env: Env, offering_id: String) -> Option<String> {
        env.storage()
            .instance()
            .get(&DataKey::Metadata(offering_id))
    }

    /// Update existing offering metadata. Owner-only.
    ///
    /// # Panics
    /// * `"unauthorized: owner only"` – caller is not the vault owner.
    ///
    /// # Events
    /// Emits topic `("metadata_updated", offering_id, caller)` with data `(old_metadata, new_metadata)`.
    pub fn update_metadata(
        env: Env,
        caller: Address,
        offering_id: String,
        metadata: String,
    ) -> String {
        caller.require_auth();
        Self::require_owner(env.clone(), caller.clone());

        assert!(
            offering_id.len() <= MAX_OFFERING_ID_LEN,
            "offering_id exceeds max length"
        );
        assert!(
            metadata.len() <= MAX_METADATA_LEN,
            "metadata exceeds max length"
        );

        let old: String = env
            .storage()
            .instance()
            .get(&DataKey::Metadata(offering_id.clone()))
            .unwrap_or(String::from_str(&env, ""));
        env.storage()
            .instance()
ta);
        env.events().publish(
            (Symbol::new(&env, "metadata_updated"), offering_id, caller),
            (old, metadata.clone()),
        );
        metadata
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn transfer_to_settlement(env: Env, amount: i128) {
        let settlement_address: Address = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, SETTLEMENT_KEY))
            .expect("settlement address not set");
        let usdc_address: Address = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, USDC_KEY))
            .expect("vault not initialized");
        let usdc = token::Client::new(&env, &usdc_address);
        usdc.transfer(&env.current_contract_address(), &settlement_address, &amount);
    }

    /// Panic with `"vault is paused"` when the circuit breaker is active.
    fn require_not_paused(env: Env) {
        assert!(!Self::is_paused(env), "vault is paused");
    }

    /// Panic with an auth error unless `caller` is the Admin **or** the Owner.
    fn require_admin_or_owner(env: Env, caller: &Address) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&StorageKey::Admin)
            .expect("vault not initialized");
        let meta = Self::get_meta(env);
        assert!(
            *caller == admin || *caller == meta.owner,
            "unauthorized: caller is not admin or owner"
        );
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod test_init_hardening;
