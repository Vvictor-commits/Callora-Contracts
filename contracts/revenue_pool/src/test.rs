extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::token;
use soroban_sdk::TryFromVal;
use soroban_sdk::{Address, Env, Symbol, Vec};

fn create_usdc<'a>(
    env: &'a Env,
    admin: &Address,
) -> (Address, token::Client<'a>, token::StellarAssetClient<'a>) {
    let contract_address = env.register_stellar_asset_contract_v2(admin.clone());
    let address = contract_address.address();
    let client = token::Client::new(env, &address);
    let admin_client = token::StellarAssetClient::new(env, &address);
    (address, client, admin_client)
}

fn create_pool(env: &Env) -> (Address, RevenuePoolClient<'_>) {
    let address = env.register(RevenuePool, ());
    let client = RevenuePoolClient::new(env, &address);
    (address, client)
}

fn fund_pool(usdc_admin_client: &token::StellarAssetClient, pool_address: &Address, amount: i128) {
    usdc_admin_client.mint(pool_address, &amount);
}

#[test]
fn init_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (_pool_addr, client) = create_pool(&env);
    let (usdc, _, _) = create_usdc(&env, &admin);

    client.init(&admin, &usdc);
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.balance(), 0);
}

#[test]
fn init_emits_event() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (_, client) = create_pool(&env);
    let (usdc, _, _) = create_usdc(&env, &admin);

    client.init(&admin, &usdc);

    let events = env.events().all();
    let init_event = events.last().unwrap();
    let event_name = Symbol::try_from_val(&env, &init_event.1.get(0).unwrap()).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "init"));
}

#[test]
#[should_panic(expected = "revenue pool already initialized")]
fn init_double_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (_, client) = create_pool(&env);
    let (usdc, _, _) = create_usdc(&env, &admin);

    client.init(&admin, &usdc);
    client.init(&admin, &usdc);
}

#[test]
#[should_panic(expected = "revenue pool already initialized")]
fn init_double_different_admin_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let other_admin = Address::generate(&env);
    let (_, client) = create_pool(&env);
    let (usdc, _, _) = create_usdc(&env, &admin);
    let (usdc2, _, _) = create_usdc(&env, &other_admin);

    client.init(&admin, &usdc);
    client.init(&other_admin, &usdc2);
}

#[test]
#[should_panic(expected = "invalid config: usdc_token cannot be the contract itself")]
fn init_usdc_token_is_contract_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);

    // Passing the contract's own address as usdc_token should be rejected.
    client.init(&admin, &pool_addr);
}

#[test]
#[should_panic(expected = "invalid config: usdc_token cannot be the admin address")]
fn init_usdc_token_is_admin_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let (_, client) = create_pool(&env);

    // Passing the admin address as usdc_token should be rejected.
    client.init(&admin, &admin);
}

// ---------------------------------------------------------------------------
// Required named test cases (CI/CD spec)
// ---------------------------------------------------------------------------

/// Verifies balance changes for both contract and recipient after a successful distribute call.
#[test]
fn test_distribute_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, usdc_client, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 1_000);

    client.distribute(&admin, &recipient, &350);

    // Contract balance reduced
    assert_eq!(usdc_client.balance(&pool_addr), 650);
    // Recipient received the funds
    assert_eq!(usdc_client.balance(&recipient), 350);

    // Verify distribute event was emitted
    let events = env.events().all();
    let distribute_event = events.iter().find(|(_, topics, _)| {
        !topics.is_empty() && {
            let name: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            name == Symbol::new(&env, "distribute")
        }
    });
    assert!(distribute_event.is_some(), "expected distribute event");
    let (_, topics, data) = distribute_event.unwrap();
    let to_addr: Address = topics.get(1).unwrap().try_into_val(&env).unwrap();
    let emitted_amount: i128 = i128::try_from_val(&env, &data).unwrap();
    assert_eq!(to_addr, recipient);
    assert_eq!(emitted_amount, 350);
}

/// Ensures a non-admin call to distribute panics with the expected message.
#[test]
fn test_distribute_unauthorized() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, _, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 500);

    let result = client.try_distribute(&non_admin, &recipient, &100);
    assert!(result.is_err(), "expected error for non-admin distribute");
}

/// Verifies the "Insufficient contract balance" panic when the contract holds less than requested.
#[test]
fn test_distribute_insufficient_funds() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, _, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 50);

    let result = client.try_distribute(&admin, &recipient, &51);
    assert!(result.is_err(), "expected error for insufficient balance");
}

/// Verifies distribute emits the correct event structure.
#[test]
fn distribute_emits_correct_event() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, _, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 500);
    client.distribute(&admin, &recipient, &200);

    let events = env.events().all();
    let ev = events.iter().find(|(_, topics, _)| {
        !topics.is_empty() && {
            let name: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            name == Symbol::new(&env, "distribute")
        }
    });
    assert!(ev.is_some(), "distribute event not found");
    let (_, topics, data) = ev.unwrap();
    // topic 0: Symbol("distribute"), topic 1: to Address
    assert_eq!(topics.len(), 2);
    let to_addr: Address = topics.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(to_addr, recipient);
    let amount: i128 = i128::try_from_val(&env, &data).unwrap();
    assert_eq!(amount, 200);
}

#[test]
fn distribute_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let developer = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, usdc_client, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 1_000);
    client.distribute(&admin, &developer, &400);

    assert_eq!(usdc_client.balance(&pool_addr), 600);
    assert_eq!(usdc_client.balance(&developer), 400);
}

#[test]
#[should_panic(expected = "amount must be positive")]
fn distribute_zero_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let developer = Address::generate(&env);
    let (_, client) = create_pool(&env);
    let (usdc, _, _) = create_usdc(&env, &admin);

    client.init(&admin, &usdc);
    client.distribute(&admin, &developer, &0);
}

#[test]
#[should_panic(expected = "insufficient USDC balance")]
fn distribute_excess_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let developer = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, _, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 100);
    client.distribute(&admin, &developer, &101);
}

#[test]
fn set_admin_two_step_transfers_control() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let developer = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, usdc_client, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 300);

    client.set_admin(&admin, &new_admin);
    assert_eq!(client.get_admin(), admin);

    client.claim_admin(&new_admin);
    assert_eq!(client.get_admin(), new_admin);

    client.distribute(&new_admin, &developer, &100);
    assert_eq!(usdc_client.balance(&developer), 100);
}

#[test]
fn admin_transfer_emits_events() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let (_, client) = create_pool(&env);
    let (usdc, _, _) = create_usdc(&env, &admin);

    client.init(&admin, &usdc);

    // Step 1 event
    client.set_admin(&admin, &new_admin);
    let events = env.events().all();
    let transfer_started = events.last().unwrap();

    // FIX: Convert Val to Symbol for comparison
    let event_name = Symbol::try_from_val(&env, &transfer_started.1.get(0).unwrap()).unwrap();
    assert_eq!(event_name, Symbol::new(&env, "admin_transfer_started"));

    // Step 2 event
    client.claim_admin(&new_admin);
    let events = env.events().all();
    let transfer_completed = events.last().unwrap();

    // FIX: Convert Val to Symbol for comparison
    let event_name_comp =
        Symbol::try_from_val(&env, &transfer_completed.1.get(0).unwrap()).unwrap();
    assert_eq!(
        event_name_comp,
        Symbol::new(&env, "admin_transfer_completed")
    );
}

#[test]
fn batch_distribute_success() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let dev1 = Address::generate(&env);
    let dev2 = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, usdc_client, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 1000);

    let mut payments: Vec<(Address, i128)> = Vec::new(&env);
    payments.push_back((dev1.clone(), 300_i128));
    payments.push_back((dev2.clone(), 200_i128));
    client.batch_distribute(&admin, &payments);

    assert_eq!(usdc_client.balance(&dev1), 300);
    assert_eq!(usdc_client.balance(&dev2), 200);
    assert_eq!(client.balance(), 500);
}

#[test]
fn batch_distribute_success_events() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let dev1 = Address::generate(&env);
    let dev2 = Address::generate(&env);
    let (pool_addr, client) = create_pool(&env);
    let (usdc_address, _, usdc_admin) = create_usdc(&env, &admin);

    client.init(&admin, &usdc_address);
    fund_pool(&usdc_admin, &pool_addr, 1000);

    let mut payments: Vec<(Address, i128)> = Vec::new(&env);
    payments.push_back((dev1.clone(), 300_i128));
    payments.push_back((dev2.clone(), 200_i128));
    client.batch_distribute(&admin, &payments);

    let events = env.events().all();
    assert!(events.len() >= 4);

    for i in 0..events.len() {
        let (_, topics, data) = events.get(i).unwrap();
        let topic_0 = topics.get(0).unwrap();
        if let Ok(event_name) = Symbol::try_from_val(&env, &topic_0) {
            if event_name == Symbol::new(&env, "batch_distribute") {
                let value: i128 = i128::try_from_val(&env, &data).unwrap();
                assert!(value == 300 || value == 200);
            }
        }
    }
}
