use exemu_gui::{HostAction, WindowCommand, WindowModel, SW_HIDE};

const SW_SHOW: i32 = 5;
const TOP: u32 = 0x0001_0010;
const PANEL: u32 = 0x0001_0020;
const BUTTON: u32 = 0x0001_0030;

fn create(hwnd: u32, parent: u32, w: u32, h: u32, visible: bool) -> WindowCommand {
    WindowCommand::Create {
        hwnd,
        parent,
        x: 120,
        y: 120,
        w,
        h,
        visible,
        title: format!("window {hwnd:#x}"),
    }
}

fn present(hwnd: u32, w: u32, h: u32) -> WindowCommand {
    WindowCommand::Present { hwnd, w, h, bgra: vec![0xFF; (w as usize) * (h as usize) * 4] }
}

fn opens(actions: &[HostAction]) -> Vec<u32> {
    actions
        .iter()
        .filter_map(|a| match a {
            HostAction::Open { hwnd, .. } => Some(*hwnd),
            _ => None,
        })
        .collect()
}

#[test]
fn a_control_never_becomes_its_own_host_window() {
    let mut m = WindowModel::new();
    let mut all = Vec::new();
    all.extend(m.plan(&create(TOP, 0, 480, 260, true)));
    all.extend(m.plan(&create(PANEL, TOP, 200, 150, true)));
    all.extend(m.plan(&create(BUTTON, PANEL, 60, 24, true)));
    all.extend(m.plan(&present(TOP, 480, 260)));

    assert_eq!(
        opens(&all),
        vec![TOP],
        "a parent plus two controls opens exactly one host window"
    );
    assert!(m.is_child(PANEL) && m.is_child(BUTTON));
    assert!(!m.is_child(TOP));
    assert!(m.is_open(TOP) && !m.is_open(BUTTON));
}

#[test]
fn a_control_that_paints_does_not_open_a_window() {
    let mut m = WindowModel::new();
    m.plan(&create(TOP, 0, 480, 260, true));
    m.plan(&create(BUTTON, TOP, 60, 24, true));
    assert!(m.plan(&present(BUTTON, 60, 24)).is_empty(), "a child present is not a host present");
    assert!(m.plan(&WindowCommand::Show { hwnd: BUTTON, cmd: SW_SHOW }).is_empty());
    assert!(
        m.plan(&WindowCommand::Destroy { hwnd: BUTTON }).is_empty(),
        "destroying a control closes no host window"
    );
    assert_eq!(m.visible_windows(), vec![TOP], "the control was never on screen");
}

#[test]
fn an_invisible_window_stays_off_screen_until_show() {
    let mut m = WindowModel::new();
    assert!(
        m.plan(&create(TOP, 0, 480, 260, false)).is_empty(),
        "a window created without WS_VISIBLE must not pop up"
    );
    assert!(!m.is_open(TOP));
    assert_eq!(m.primary(), None, "and it takes no input while it is not on screen");

    let shown = m.plan(&WindowCommand::Show { hwnd: TOP, cmd: SW_SHOW });
    assert_eq!(
        shown,
        vec![
            HostAction::Open { hwnd: TOP, w: 480, h: 260, title: format!("window {TOP:#x}") },
            HostAction::Front { hwnd: TOP },
        ]
    );
    assert_eq!(m.primary(), Some(TOP));
}

#[test]
fn hiding_a_window_orders_it_out_and_keeps_it_alive() {
    let mut m = WindowModel::new();
    m.plan(&create(TOP, 0, 480, 260, true));
    assert_eq!(m.plan(&WindowCommand::Show { hwnd: TOP, cmd: SW_HIDE }), vec![HostAction::Hide { hwnd: TOP }]);
    assert!(m.is_open(TOP), "SW_HIDE hides, it does not destroy");
    assert!(!m.visible(TOP));
    assert_eq!(m.primary(), None);

    assert_eq!(
        m.plan(&WindowCommand::Show { hwnd: TOP, cmd: SW_SHOW }),
        vec![HostAction::Front { hwnd: TOP }],
        "showing it again reuses the window instead of opening a second one"
    );
    assert_eq!(m.primary(), Some(TOP));
}

#[test]
fn input_follows_the_first_visible_top_level() {
    let mut m = WindowModel::new();
    let second = TOP + 0x100;
    m.plan(&create(TOP, 0, 480, 260, true));
    m.plan(&create(second, 0, 300, 200, true));
    assert_eq!(m.visible_windows(), vec![TOP, second], "creation order, as win32k walks it");
    assert_eq!(m.primary(), Some(TOP));

    m.plan(&WindowCommand::Show { hwnd: TOP, cmd: SW_HIDE });
    assert_eq!(m.primary(), Some(second), "hiding the first hands input to the next one");

    m.plan(&WindowCommand::Destroy { hwnd: second });
    assert_eq!(m.primary(), None, "with nothing visible there is no window to route input to");
}

#[test]
fn a_resize_is_emitted_only_when_the_size_really_changes() {
    let mut m = WindowModel::new();
    m.plan(&create(TOP, 0, 480, 260, true));
    assert!(
        m.plan(&WindowCommand::Pos { hwnd: TOP, rect: [120, 120, 480, 260] }).is_empty(),
        "the create-time geometry is not a resize"
    );
    assert_eq!(
        m.plan(&WindowCommand::Pos { hwnd: TOP, rect: [120, 120, 640, 400] }),
        vec![HostAction::Resize { hwnd: TOP, w: 640, h: 400 }]
    );
    assert!(m.plan(&WindowCommand::Pos { hwnd: TOP, rect: [0, 0, 0, 0] }).is_empty());
}

#[test]
fn destroying_a_window_closes_it_exactly_once() {
    let mut m = WindowModel::new();
    m.plan(&create(TOP, 0, 480, 260, true));
    assert_eq!(
        m.plan(&WindowCommand::Destroy { hwnd: TOP }),
        vec![HostAction::Close { hwnd: TOP }]
    );
    assert!(m.plan(&WindowCommand::Destroy { hwnd: TOP }).is_empty());
    assert!(!m.is_open(TOP));
}

#[test]
fn a_present_opens_a_window_the_guest_never_announced() {
    let mut m = WindowModel::new();
    let actions = m.plan(&present(TOP, 320, 240));
    assert_eq!(
        actions,
        vec![
            HostAction::Open { hwnd: TOP, w: 320, h: 240, title: "exemu".to_string() },
            HostAction::Front { hwnd: TOP },
            HostAction::Present { hwnd: TOP },
        ]
    );
    assert_eq!(m.primary(), Some(TOP));
    assert_eq!(m.plan(&present(TOP, 320, 240)), vec![HostAction::Present { hwnd: TOP }]);
}

#[test]
fn a_title_change_reaches_only_an_open_window() {
    let mut m = WindowModel::new();
    m.plan(&create(TOP, 0, 480, 260, false));
    assert!(
        m.plan(&WindowCommand::SetTitle { hwnd: TOP, title: "later".into() }).is_empty(),
        "nothing to retitle before the window exists"
    );
    let shown = m.plan(&WindowCommand::Show { hwnd: TOP, cmd: SW_SHOW });
    assert_eq!(
        opens(&shown),
        vec![TOP],
        "the pending title is carried into the window when it opens"
    );
    assert!(matches!(
        shown.first(),
        Some(HostAction::Open { title, .. }) if title == "later"
    ));
    assert_eq!(
        m.plan(&WindowCommand::SetTitle { hwnd: TOP, title: "now".into() }),
        vec![HostAction::Title { hwnd: TOP, title: "now".into() }]
    );
}
