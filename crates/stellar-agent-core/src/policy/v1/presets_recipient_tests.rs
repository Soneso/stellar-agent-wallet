fn w_address(seed: u8, id: u64) -> String {
    format!(
        "{}",
        stellar_strkey::MuxedContract {
            contract_id: [seed; 32],
            id
        }
    )
}

fn recipient_body() -> String {
    policy_body(PROFILE, &derived("api-day", false, true))
}

fn recipient_edit(body: &str, recipient: &str, tools: &[&str]) -> RecipientEdit {
    add_payment_recipient(body, MAINNET_PASSPHRASE, recipient, tools).unwrap()
}

fn addition(body: &str, recipient: &str, tools: &[&str]) -> RecipientAddition {
    match recipient_edit(body, recipient, tools) {
        RecipientEdit::Added(added) => added,
        other => panic!("expected an addition: {other:?}"),
    }
}

fn listed(body: &str, recipient: &str) -> RecipientListed {
    match recipient_edit(body, recipient, &[]) {
        RecipientEdit::Listed(listed) => listed,
        other => panic!("expected existing coverage: {other:?}"),
    }
}

fn recipient_refusal(body: &str, recipient: &str, tools: &[&str], code: &str) -> String {
    let error = add_payment_recipient(body, MAINNET_PASSPHRASE, recipient, tools).unwrap_err();
    assert_eq!(error.code(), code);
    error.to_string()
}

fn recipient_lists(body: &str, tools: &[&str], edit: impl Fn(&mut InlineTable)) -> String {
    edit_rules(body, tools, |criteria| {
        for value in criteria.iter_mut() {
            let list = value.as_inline_table_mut().unwrap();
            if list.get("kind").and_then(Value::as_str) == Some("counterparty_allowlist") {
                edit(list);
            }
        }
    })
}

fn all_recipient_lists(body: &str, edit: impl Fn(&mut InlineTable)) -> String {
    recipient_lists(body, MAINNET_VALUE_OUT_TOOLS, edit)
}

fn first_rule(body: &str, tool: &str, chain: &str, decision: &str) -> String {
    let offset = body.find("[[rules]]").unwrap();
    format!(
        "{}[[rules]]\nmatch = {{ tool = {tool:?}, chain = {chain:?} }}\ndecision = {decision:?}\ncriteria = [{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [] }}]\n{}",
        &body[..offset],
        &body[offset..]
    )
}

#[test]
fn classify_recipient_forms() {
    for (recipient, kind, muxed_contract) in [
        (account(7), "G_ACCOUNT", false),
        (muxed(7, 9), "G_ACCOUNT", false),
        (contract(8), "C_ACCOUNT", false),
        (w_address(8, 9), "C_ACCOUNT", true),
    ] {
        let form = classify_recipient(&recipient).unwrap();
        assert_eq!((form.kind, form.muxed_contract), (kind, muxed_contract));
    }
}

#[test]
fn classify_recipient_bases() {
    for (recipient, base) in [
        (account(7), account(7)),
        (muxed(7, 9), account(7)),
        (contract(8), contract(8)),
        (w_address(8, 9), contract(8)),
    ] {
        assert_eq!(classify_recipient(&recipient).unwrap().base, base);
    }
}

#[test]
fn classify_recipient_refuses_other_strkeys() {
    let other = [
        stellar_strkey::ed25519::PrivateKey([7; 32])
            .as_unredacted()
            .to_string()
            .to_string(),
        format!("{}", stellar_strkey::PreAuthTx([7; 32])),
        format!("{}", stellar_strkey::HashX([7; 32])),
        format!(
            "{}",
            stellar_strkey::ed25519::SignedPayload::new([7; 32], &[1, 2]).unwrap()
        ),
        format!("{}", stellar_strkey::LiquidityPool([7; 32])),
        format!("{}", stellar_strkey::ClaimableBalance::V0([7; 32])),
        "invalid".to_owned(),
    ];
    for recipient in other {
        assert_eq!(
            classify_recipient(&recipient),
            Err(RecipientRefusal::Invalid)
        );
    }
}

#[test]
fn classify_recipient_never_echoes() {
    let input = "private-input-marker";
    let refusal = classify_recipient(input).unwrap_err();
    assert_eq!(refusal.code(), "profile.policy_recipient_invalid");
    assert!(!refusal.to_string().contains(input));
    assert!(refusal.to_string().contains("G, M, C, or W"));
}

#[test]
fn payment_recipient_updates_every_effective_list() {
    let body = recipient_lists(&recipient_body(), &["stellar_pay"], |list| {
        list.insert("gate_inflows", true.into());
    });
    let body = edit_rules(&body, &["stellar_pay"], |criteria| {
        let list = criteria
            .iter()
            .find(|v| v.as_inline_table().is_some_and(address_list))
            .unwrap()
            .clone();
        criteria.push(list);
    });
    let added = addition(&body, &account(7), &[]);
    for rule in read_rules(&doc(&added.body))
        .iter()
        .filter(|rule| MAINNET_VALUE_OUT_TOOLS.contains(&rule.tool))
    {
        for list in rule.of_kind("counterparty_allowlist") {
            assert!(
                recipient_entries(list).any(|entry| entry == account(7)),
                "{}",
                rule.tool
            );
        }
    }
}

#[test]
fn targets_are_first_matching_rules() {
    let body = recipient_body();
    let shadowed = &body[body.find("[[rules]]").unwrap()..];
    let added = addition(
        &first_rule(&body, "stellar_pay", "*", "allow"),
        &account(7),
        &["stellar_pay"],
    );
    assert!(added.body.ends_with(shadowed));
    assert_eq!(added.updated_rules, [0]);
}

#[test]
fn wildcard_rule_is_targeted() {
    let body = first_rule(&recipient_body(), "*", "*", "allow");
    let added = addition(&body, &account(7), &[]);
    assert_eq!(added.updated_rules, [0]);
    assert!(added.scope[0].wildcard);
}

#[test]
fn deny_stops_target_search() {
    let body = first_rule(&recipient_body(), "stellar_pay", "*", "deny");
    let added = addition(&body, &account(7), &[]);
    assert_eq!(
        added.denied_tools,
        [
            "stellar_pay",
            "stellar_create_account",
            "stellar_create_account_commit"
        ]
    );
    assert!(!added.updated_rules.contains(&1));
}

#[test]
fn chain_mismatch_is_not_targeted() {
    let body = first_rule(&recipient_body(), "stellar_pay", "stellar:testnet", "allow");
    let added = addition(&body, &account(7), &["stellar_pay"]);
    assert_eq!(added.updated_rules, [1]);
    assert_eq!(
        doc(&body)["rules"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap()
            .to_string(),
        doc(&added.body)["rules"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap()
            .to_string()
    );
}

#[test]
fn explicit_tool_without_rule_refuses() {
    for tools in [
        vec!["stellar_create_account"],
        vec!["stellar_pay", "stellar_create_account"],
    ] {
        recipient_refusal(
            &recipient_body(),
            &account(7),
            &tools,
            "profile.policy_recipient_list_missing",
        );
    }
}

fn ungated_body() -> String {
    edit_rules(&recipient_body(), &["stellar_pay"], |criteria| {
        criteria.retain(|value| !value.as_inline_table().is_some_and(address_list));
    })
}

#[test]
fn ungated_rule_is_reported_not_edited() {
    let body = ungated_body();
    let added = addition(&body, &account(7), &[]);
    assert_eq!(
        doc(&body)["rules"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap()
            .to_string(),
        doc(&added.body)["rules"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap()
            .to_string()
    );
    assert!(!added.updated_rules.contains(&0));
}

#[test]
fn ungated_tools_lists_the_tool() {
    assert_eq!(
        addition(&ungated_body(), &account(7), &[]).ungated_tools,
        ["stellar_pay"]
    );
}

#[test]
fn no_address_list_refuses() {
    recipient_refusal(
        &ungated_body(),
        &account(7),
        &["stellar_pay"],
        "profile.policy_recipient_list_missing",
    );
}

#[test]
fn reserved_kind_list_refuses() {
    for reserved in ["SEP10_IDENTITY", "ONE_TIME_ADDRESS"] {
        let body = all_recipient_lists(&recipient_body(), |list| {
            list["kinds"].as_array_mut().unwrap().push(reserved);
        });
        recipient_refusal(
            &body,
            &account(7),
            &[],
            "profile.policy_recipient_list_unsupported",
        );
    }
}

#[test]
fn listed_recipient_changes_nothing() {
    let body = add_recipient(&recipient_body(), &account(7)).unwrap();
    assert_eq!(listed(&body, &account(7)).covered_by, account(7));
}

#[test]
fn listed_recipient_reports_unchanged() {
    let body = add_recipient(&recipient_body(), &account(7)).unwrap();
    assert!(matches!(
        recipient_edit(&body, &account(7), &[]),
        RecipientEdit::Listed(_)
    ));
}

#[test]
fn muxed_recipient_covered_by_base_is_listed() {
    let body = add_recipient(&recipient_body(), &account(7)).unwrap();
    assert_eq!(listed(&body, &muxed(7, 9)).covered_by, account(7));
}

#[test]
fn w_covered_by_base_contract_is_listed() {
    let body = add_recipient(&recipient_body(), &contract(7)).unwrap();
    assert_eq!(listed(&body, &w_address(7, 9)).covered_by, contract(7));
}

#[test]
fn mixed_exact_and_base_reports_the_base() {
    let body = add_recipient(&recipient_body(), &account(7)).unwrap();
    let body = recipient_lists(&body, &["stellar_pay"], |list| {
        list.insert("allowlist", Value::from_iter([muxed(7, 9)]));
    });
    assert_eq!(listed(&body, &muxed(7, 9)).covered_by, account(7));
}

#[test]
fn listed_precedes_differing_lists() {
    let body = add_recipient(&recipient_body(), &account(7)).unwrap();
    let body = recipient_lists(&body, &["stellar_pay"], |list| {
        list["allowlist"].as_array_mut().unwrap().push(account(8));
    });
    assert_eq!(listed(&body, &account(7)).covered_by, account(7));
}

#[test]
fn account_with_only_muxed_entries_is_added() {
    let body = add_recipient(&recipient_body(), &muxed(7, 9)).unwrap();
    assert!(addition(&body, &account(7), &[]).body.contains(&account(7)));
}

#[test]
fn base_c_with_only_w_is_added() {
    let body = add_recipient(&recipient_body(), &w_address(7, 9)).unwrap();
    assert!(
        addition(&body, &contract(7), &[])
            .body
            .contains(&contract(7))
    );
}

#[test]
fn w_recipient_is_added_with_contract_kind() {
    let added = addition(&recipient_body(), &w_address(7, 9), &[]);
    assert_eq!(added.kind, "C_ACCOUNT");
    assert!(
        payment_lists(&added.body)
            .iter()
            .all(|(_, list)| list == &[w_address(7, 9)])
    );
}

#[test]
#[serial_test::serial]
fn w_entry_covers_only_itself() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let added = addition(&recipient_body(), &w_address(7, 9), &[]);
    for (to, expected) in [
        (w_address(7, 9), "allow"),
        (w_address(7, 10), "deny"),
        (contract(7), "deny"),
    ] {
        assert_eq!(
            label(&x402(
                &verified_engine(&added.body),
                CREATE_TOOL,
                &to,
                1,
                T0
            )),
            expected
        );
    }
}

#[test]
#[serial_test::serial]
fn recipient_kind_is_appended_when_missing() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let body = recipient_body().replace("\"G_ACCOUNT\", \"C_ACCOUNT\"", "\"G_ACCOUNT\"");
    let added = addition(&body, &contract(7), &[]);
    assert_eq!(added.kinds_added, added.updated_rules);
    assert_eq!(
        label(&x402(
            &verified_engine(&added.body),
            CREATE_TOOL,
            &contract(7),
            1,
            T0
        )),
        "allow"
    );
}

#[test]
#[serial_test::serial]
fn inert_recipient_entry_is_not_listed() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let recipient = contract(7);
    let body = all_recipient_lists(&recipient_body(), |list| {
        list.insert("kinds", Value::from_iter(["G_ACCOUNT"]));
        list.insert("allowlist", Value::from_iter([recipient.clone()]));
    });
    let added = addition(&body, &recipient, &[]);
    assert_eq!(added.kinds_added, [0, 1, 2, 3]);
    assert_eq!(added.updated_rules, added.kinds_added);
    assert_eq!(
        label(&x402(
            &verified_engine(&added.body),
            CREATE_TOOL,
            &recipient,
            1,
            T0
        )),
        "allow"
    );
    assert!(
        payment_lists(&added.body)
            .iter()
            .all(|(_, list)| list == std::slice::from_ref(&recipient))
    );
}

#[test]
fn kind_append_keeps_order() {
    let body = all_recipient_lists(&recipient_body(), |list| {
        list.insert("kinds", Value::from_iter(["KNOWN_ISSUER", "G_ACCOUNT"]));
    });
    let added = addition(&body, &contract(7), &[]);
    for (_, criteria) in rules_of(&doc(&added.body)) {
        for list in of_kind(&criteria, "counterparty_allowlist") {
            assert_eq!(
                list["kinds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["KNOWN_ISSUER", "G_ACCOUNT", "C_ACCOUNT"]
            );
        }
    }
}

#[test]
fn kinds_are_never_removed() {
    let added = addition(&recipient_body(), &account(7), &[]);
    assert_eq!(
        added
            .body
            .matches("kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"]")
            .count(),
        4
    );
}

#[test]
fn kind_append_activating_g_entries_refuses() {
    for entry in [account(8), muxed(8, 9)] {
        let body = all_recipient_lists(&recipient_body(), |list| {
            list.insert("kinds", Value::from_iter(["C_ACCOUNT"]));
            list.insert("allowlist", Value::from_iter([entry.clone()]));
        });
        assert!(
            recipient_refusal(
                &body,
                &account(7),
                &[],
                "profile.policy_recipient_kind_conflict"
            )
            .contains(&entry)
        );
    }
}

#[test]
fn kind_append_activating_w_entries_refuses() {
    for entry in [contract(8), w_address(8, 9)] {
        let body = all_recipient_lists(&recipient_body(), |list| {
            list.insert("kinds", Value::from_iter(["G_ACCOUNT"]));
            list.insert("allowlist", Value::from_iter([entry.clone()]));
        });
        assert!(
            recipient_refusal(
                &body,
                &contract(7),
                &[],
                "profile.policy_recipient_kind_conflict"
            )
            .contains(&entry)
        );
    }
}

fn issuer_body() -> String {
    all_recipient_lists(&recipient_body(), |list| {
        list["kinds"].as_array_mut().unwrap().push("KNOWN_ISSUER");
    })
}

#[test]
#[serial_test::serial]
fn recipient_insert_does_not_expand_issuer_authority() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let body = add_recipient(&issuer_body(), &account(7)).unwrap();
    assert_eq!(
        label(&pay(&verified_engine(&body), &account(7), 1, T0)),
        "deny"
    );
    recipient_refusal(
        &body,
        ISSUER,
        &[],
        "profile.policy_recipient_list_unsupported",
    );
}

#[test]
#[serial_test::serial]
fn known_issuer_g_already_accepted_is_added() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let body = all_recipient_lists(&issuer_body(), |list| {
        list.insert("allowlist", Value::from_iter([format!("USDC:{ISSUER}")]));
    });
    let added = addition(&body, ISSUER, &[]);
    assert_eq!(
        label(&pay(&verified_engine(&added.body), ISSUER, 1, T0)),
        "allow"
    );
}

#[test]
#[serial_test::serial]
fn muxed_entry_never_acts_as_issuer() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let added = addition(&issuer_body(), &muxed(7, 9), &[]);
    assert_eq!(
        label(&pay(&verified_engine(&added.body), &muxed(7, 9), 1, T0)),
        "deny"
    );
}

#[test]
fn issuer_refusal_names_the_ways() {
    let text = recipient_refusal(
        &issuer_body(),
        &account(7),
        &[],
        "profile.policy_recipient_list_unsupported",
    );
    for expected in [
        "rule 0",
        "assets issued by this G",
        "every recipient",
        "without KNOWN_ISSUER",
        "hand edit signed with profile sign-policy",
    ] {
        assert!(text.contains(expected), "{text}");
    }
}

#[test]
fn differing_lists_refuse_ambiguous() {
    let body = recipient_lists(&recipient_body(), &["stellar_pay"], |list| {
        list.insert("allowlist", Value::from_iter([account(8)]));
    });
    let text = recipient_refusal(
        &body,
        &account(7),
        &[],
        "profile.policy_counterparty_ambiguous",
    );
    for tool in PAYMENT_TOOLS {
        assert!(text.contains(tool));
    }
    assert!(text.contains("Supply a selection whose target lists hold the same entries."));
    assert!(!text.contains("--tool"));
}

#[test]
fn issuer_and_domain_entries_make_lists_differ() {
    for (kind, first, second) in [
        (
            "KNOWN_ISSUER",
            format!("USDC:{ISSUER}"),
            format!("USDC:{OTHER_ISSUER}"),
        ),
        ("HOME_DOMAIN", "one.example".into(), "two.example".into()),
    ] {
        let body = all_recipient_lists(&recipient_body(), |list| {
            list["kinds"].as_array_mut().unwrap().push(kind);
            list.insert("allowlist", Value::from_iter([first.clone()]));
        });
        let body = recipient_lists(&body, &["stellar_pay"], |list| {
            list.insert("allowlist", Value::from_iter([second.clone()]));
        });
        let text = recipient_refusal(
            &body,
            &contract(7),
            &[],
            "profile.policy_counterparty_ambiguous",
        );
        assert!(text.contains(&first) && text.contains(&second), "{text}");
    }
}

#[test]
fn explicit_scope_ambiguity_precedes_kind_conflict() {
    let body = first_rule(&recipient_body(), "*", "*", "allow").replace(
        "kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = []",
        &format!("kinds = [\"G_ACCOUNT\"], allowlist = [{:?}]", contract(8)),
    );
    let text = recipient_refusal(
        &body,
        &contract(7),
        &["stellar_pay"],
        "profile.policy_counterparty_ambiguous",
    );
    assert!(text.contains("rule 0 shares its list"));
}

#[test]
fn lists_compare_by_listed_sets() {
    let body = all_recipient_lists(&recipient_body(), |list| {
        list.insert("allowlist", Value::from_iter([account(8), account(9)]));
    });
    let body = recipient_lists(&body, &["stellar_pay"], |list| {
        list.insert(
            "allowlist",
            Value::from_iter([account(9), account(8), account(9)]),
        );
    });
    assert_eq!(addition(&body, &account(7), &[]).updated_rules.len(), 4);
}

#[test]
fn inert_entries_do_not_make_lists_differ() {
    let body = recipient_body().replace("\"G_ACCOUNT\", \"C_ACCOUNT\"", "\"G_ACCOUNT\"");
    let body = recipient_lists(&body, &["stellar_pay"], |list| {
        list.insert("allowlist", Value::from_iter([contract(8)]));
    });
    assert_eq!(addition(&body, &account(7), &[]).updated_rules.len(), 4);
}

#[test]
fn tool_selection_edits_selected_rules_only() {
    let body = recipient_body();
    let added = addition(&body, &account(7), &["stellar_pay"]);
    assert_eq!(added.updated_rules, [0]);
    let rules = doc(&body)["rules"].as_array_of_tables().unwrap().clone();
    let after = doc(&added.body)["rules"]
        .as_array_of_tables()
        .unwrap()
        .clone();
    for index in 1..rules.len() {
        assert_eq!(
            rules.get(index).unwrap().to_string(),
            after.get(index).unwrap().to_string()
        );
    }
}

#[test]
fn explicit_tool_refuses_unselected_payment_consumer() {
    let body = first_rule(&recipient_body(), "*", "*", "allow");
    let text = recipient_refusal(
        &body,
        &account(7),
        &["stellar_pay"],
        "profile.policy_counterparty_ambiguous",
    );
    assert!(text.contains("Select these payment tools too: stellar_pay_commit"));
    assert!(!text.contains("--tool"));
}

#[test]
fn explicit_tool_refuses_non_payment_consumer() {
    let body = first_rule(&recipient_body(), "*", "*", "allow");
    let text = recipient_refusal(
        &body,
        &account(7),
        MAINNET_VALUE_OUT_TOOLS,
        "profile.policy_counterparty_ambiguous",
    );
    assert!(text.contains("non-payment tools"));
    assert!(text.contains("Supply an empty selection"));
    assert!(!text.contains("--tool"));
}

#[test]
fn wildcard_scope_refuses_even_when_known_consumers_are_selected() {
    let mut body = first_rule(&recipient_body(), "*", "*", "allow");
    for tool in MAINNET_READ_ONLY_TOOLS
        .iter()
        .chain(MAINNET_TRUSTLINE_TOOLS)
        .chain(MAINNET_CLAIM_TOOLS)
    {
        body = first_rule(&body, tool, "*", "allow");
    }
    let rules = read_rules(&doc(&body))
        .into_iter()
        .map(|rule| rule.tool.to_owned())
        .collect::<Vec<_>>();
    let wildcard = rules.iter().position(|tool| tool == "*").unwrap();
    let added = addition(&body, &account(7), &[]);
    assert_eq!(added.scope[0].rule, wildcard);
    assert_eq!(added.scope[0].tools, MAINNET_VALUE_OUT_TOOLS);
    let text = recipient_refusal(
        &body,
        &account(7),
        MAINNET_VALUE_OUT_TOOLS,
        "profile.policy_counterparty_ambiguous",
    );
    assert!(text.contains("every tool without an earlier match"));
}

#[test]
fn wildcard_scope_names_non_payment_tools() {
    let added = addition(
        &first_rule(&recipient_body(), "*", "*", "allow"),
        &account(7),
        &[],
    );
    let expected: Vec<_> = MAINNET_READ_ONLY_TOOLS
        .iter()
        .chain(MAINNET_VALUE_OUT_TOOLS)
        .chain(MAINNET_TRUSTLINE_TOOLS)
        .chain(MAINNET_CLAIM_TOOLS)
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        added.scope,
        [RuleScope {
            rule: 0,
            tools: expected,
            wildcard: true
        }]
    );
}

fn domain_body(unlisted: bool) -> String {
    all_recipient_lists(
        &policy_body(PROFILE, &derived("api-day", unlisted, true)),
        |list| {
            list["kinds"].as_array_mut().unwrap().push("HOME_DOMAIN");
        },
    )
}

#[test]
fn domain_list_without_unlisted_is_split() {
    let added = addition(&domain_body(false), &account(7), &[]);
    validate_unsigned_policy(&added.body, PROFILE, MAINNET_PASSPHRASE).unwrap();
    assert_eq!(added.split_rules, [0, 1, 2, 3]);
    for (_, criteria) in rules_of(&doc(&added.body)).into_iter().take(4) {
        let lists = of_kind(&criteria, "counterparty_allowlist");
        assert_eq!(lists.len(), 2);
        assert!(selects(lists[0], "HOME_DOMAIN") && !selects(lists[0], "G_ACCOUNT"));
        assert!(
            selects(lists[1], "G_ACCOUNT") && recipient_entries(lists[1]).eq([account(7).as_str()])
        );
    }
}

#[test]
#[serial_test::serial]
fn domain_split_appends_the_missing_contract_kind() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    struct DomainBinding(String);
    impl super::super::AccountIdentityView for DomainBinding {
        fn home_domain(&self) -> Option<String> {
            Some("recipient.example".into())
        }
        fn account_id(&self) -> &str {
            &self.0
        }
    }
    impl super::super::CounterpartyCacheView for DomainBinding {
        fn has_resolved(&self, domain: &str) -> bool {
            domain == "recipient.example"
        }
        fn is_account_listed(&self, domain: &str, account: &str) -> bool {
            domain == "recipient.example" && account == self.0
        }
    }
    let body = domain_body(false).replace("\"G_ACCOUNT\", \"C_ACCOUNT\"", "\"G_ACCOUNT\"");
    let body = all_recipient_lists(&body, |list| {
        list.insert("allowlist", Value::from_iter(["recipient.example"]));
    });
    let added = addition(&body, &contract(7), &[]);
    assert_eq!(added.kinds_added, [0, 1, 2, 3]);
    assert_eq!(added.split_rules, added.kinds_added);
    validate_unsigned_policy(&added.body, PROFILE, MAINNET_PASSPHRASE).unwrap();
    for (_, criteria) in rules_of(&doc(&added.body)).into_iter().take(4) {
        let lists = of_kind(&criteria, "counterparty_allowlist");
        assert!(selects(lists[1], "C_ACCOUNT"));
    }
    let binding = DomainBinding(contract(7));
    let evaluate = |body: &str| {
        verified_engine(body)
            .evaluate_with_value(
                &tool_on(CREATE_TOOL, Net::Mainnet),
                &serde_json::json!({}),
                &mainnet_profile(),
                x402_value(&contract(7), 1),
                None,
                Some(&binding),
                Some(&binding),
                None,
                None,
                T0,
            )
            .unwrap()
    };
    assert_eq!(label(&evaluate(&body)), "deny");
    assert_eq!(label(&evaluate(&added.body)), "allow");
    assert_eq!(
        label(&x402(
            &verified_engine(&added.body),
            CREATE_TOOL,
            &contract(7),
            1,
            T0
        )),
        "deny"
    );
}

#[test]
#[serial_test::serial]
fn domain_split_preserves_other_recipients() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let body = domain_body(false);
    let added = addition(&body, &account(7), &[]);
    for recipient in [account(8), muxed(8, 9), contract(8), w_address(8, 9)] {
        let before = label(&x402(
            &verified_engine(&body),
            CREATE_TOOL,
            &recipient,
            1,
            T0,
        ));
        assert_eq!(before, "deny");
        assert_eq!(
            label(&x402(
                &verified_engine(&added.body),
                CREATE_TOOL,
                &recipient,
                1,
                T0
            )),
            before
        );
    }
}

#[test]
fn domain_list_with_unlisted_refuses() {
    let text = recipient_refusal(
        &domain_body(true),
        &account(7),
        &[],
        "profile.policy_recipient_list_unsupported",
    );
    assert!(text.contains("merged address and domain outcome"));
    assert!(text.contains("address check alone"));
}

#[test]
fn edit_preserves_unlisted_bytes() {
    let body = policy_body(PROFILE, &derived("api-day", true, true));
    let added = addition(&body, &account(7), &[]);
    assert_eq!(
        added.body.replace(
            &format!("allowlist = [\"{}\"]", account(7)),
            "allowlist = []"
        ),
        body
    );
}

#[test]
fn edit_preserves_unrelated_criteria() {
    let body = all_recipient_lists(&recipient_body(), |list| {
        list.insert("gate_inflows", true.into());
    });
    let added = addition(&body, &account(7), &[]);
    assert_eq!(
        added.body.replace(
            &format!("allowlist = [\"{}\"]", account(7)),
            "allowlist = []"
        ),
        body
    );
}

#[test]
fn edit_preserves_comments_and_mainnet() {
    let body = format!(
        "# Keep this comment.\n{}\n[mainnet]\nclassic_max_fee_per_op_stroops = 10000 # Keep the fee.\n",
        recipient_body()
    );
    let added = addition(&body, &account(7), &[]);
    assert_eq!(
        added.body.replace(
            &format!("allowlist = [\"{}\"]", account(7)),
            "allowlist = []"
        ),
        body
    );
}

#[test]
#[serial_test::serial]
fn edited_body_loads_and_meets_minimum() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let body = format!(
        "{}\n[mainnet]\nclassic_max_fee_per_op_stroops = 10000\n",
        recipient_body()
    );
    let added = addition(&body, &account(7), &[]);
    validate_unsigned_policy(&added.body, PROFILE, MAINNET_PASSPHRASE).unwrap();
    let before = mainnet_minimum::evaluate(&doc(&body), &mainnet_profile(), PROFILE);
    let after = mainnet_minimum::evaluate(&doc(&added.body), &mainnet_profile(), PROFILE);
    for (before, after) in before.iter().zip(after) {
        assert_eq!(before.status, after.status);
    }
}

#[test]
#[serial_test::serial]
fn edited_body_pays_as_summarized() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let mut body = recipient_body();
    for recipient in [account(7), muxed(8, 9), contract(7), w_address(8, 9)] {
        body = addition(&body, &recipient, &[]).body;
    }
    let summary = summary_of(&body);
    for (recipient, expected) in [
        (account(7), "allow"),
        (muxed(8, 9), "allow"),
        (account(8), "deny"),
        (contract(7), "allow"),
        (w_address(8, 9), "allow"),
        (contract(8), "deny"),
        (account(9), "deny"),
    ] {
        let stated = summary.recipients.listed.iter().any(|entry| {
            entry.recipient == recipient
                && entry.treatment == Agreed::Uniform(Some(Treatment::Allowed))
        });
        assert_eq!(stated, expected == "allow", "{recipient}");
        assert_eq!(
            label(&x402(
                &verified_engine(&body),
                CREATE_TOOL,
                &recipient,
                1,
                T0
            )),
            expected
        );
    }
}

#[test]
fn unparsable_body_refuses_body_invalid() {
    let text = recipient_refusal(
        "secret = private-input-marker",
        &account(7),
        &[],
        "profile.policy_body_invalid",
    );
    assert_eq!(text, "the policy body does not parse at byte 9");
    assert!(!text.contains("private-input-marker"));
}

#[test]
fn unknown_network_refuses_before_targeting() {
    for body in [
        first_rule(&recipient_body(), "*", "*", "allow"),
        "secret = private-input-marker".into(),
    ] {
        let error =
            add_payment_recipient(&body, "unrecognized-network", &account(7), &[]).unwrap_err();
        assert_eq!(error, RecipientRefusal::UnknownNetwork);
        assert_eq!(error.code(), "profile.policy_network_unknown");
        assert_eq!(error.to_string(), "the passphrase is not a known network");
    }
}

#[test]
fn rule_indexes_are_zero_based() {
    let added = addition(&recipient_body(), &account(7), &[]);
    assert_eq!(added.updated_rules, [0, 1, 2, 3]);
    assert_eq!(
        added
            .scope
            .iter()
            .map(|scope| scope.rule)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
}

#[test]
fn tools_are_deduplicated_in_list_order() {
    let body = edit_rules(&ungated_body(), &["stellar_pay_commit"], |criteria| {
        criteria.retain(|value| !value.as_inline_table().is_some_and(address_list));
    });
    let added = addition(
        &body,
        &account(7),
        &[
            "stellar_pay_commit",
            "stellar_pay",
            "stellar_pay_commit",
            CREATE_TOOL,
            "stellar_pay",
        ],
    );
    assert_eq!(
        added
            .scope
            .iter()
            .flat_map(|scope| scope.tools.iter().map(String::as_str))
            .collect::<Vec<_>>(),
        ["stellar_pay", "stellar_pay_commit", CREATE_TOOL]
    );
    assert_eq!(added.updated_rules, [2]);
    assert_eq!(added.ungated_tools, ["stellar_pay", "stellar_pay_commit"]);
}
