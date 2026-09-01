import UIKit

/// Full-screen PIN entry overlay rendered and controlled entirely by the SDK.
/// The host app never sees raw digit input — only the encrypted block returned on confirm.
internal final class PinEntryViewController: UIViewController {

    private static let minLength = 4
    private static let maxLength = 6
    private static let keySize:  CGFloat = 72
    private static let keyGap:   CGFloat = 16
    private static let dotSize:  CGFloat = 14

    private let theme: PinTheme
    private var digits: [Character] = []
    private var continuation: CheckedContinuation<[Character], Error>?

    // MARK: - UI elements

    private lazy var titleLabel: UILabel = {
        let l = UILabel()
        l.text          = theme.strings.title
        l.textColor     = theme.colors.titleColor
        l.font          = theme.typography.font(size: theme.typography.titleSize, weight: .semibold)
        l.textAlignment = .center
        return l
    }()

    private lazy var subtitleLabel: UILabel = {
        let l = UILabel()
        l.text          = theme.strings.subtitle
        l.textColor     = theme.colors.subtitleColor
        l.font          = theme.typography.font(size: theme.typography.subtitleSize)
        l.textAlignment = .center
        return l
    }()

    private lazy var dotStack: UIStackView = {
        let stack = UIStackView()
        stack.axis    = .horizontal
        stack.spacing = 12
        for _ in 0..<Self.maxLength {
            let dot = makeDot(filled: false)
            stack.addArrangedSubview(dot)
        }
        return stack
    }()

    private lazy var closeButton: UIButton = {
        let b = UIButton(type: .system)
        let img = UIImage(systemName: "xmark")
        b.setImage(img, for: .normal)
        b.tintColor = theme.colors.subtitleColor
        b.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
        return b
    }()

    private lazy var cancelButton: UIButton = {
        let b = UIButton(type: .system)
        b.setTitle("Cancel", for: .normal)
        b.setTitleColor(theme.colors.subtitleColor, for: .normal)
        b.titleLabel?.font = theme.typography.font(size: 15)
        b.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
        return b
    }()

    // MARK: - Init

    init(theme: PinTheme) {
        self.theme = theme
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .overFullScreen
        modalTransitionStyle   = .crossDissolve
    }

    required init?(coder: NSCoder) { fatalError() }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = theme.colors.background
        buildLayout()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Swipe-dismiss or parent dismiss — cancel the continuation
        guard let cont = continuation else { return }
        continuation = nil
        zeroClear()
        cont.resume(throwing: HashamMobileError.invalidPin("Cancelled"))
    }

    // MARK: - Public awaitable entry point

    func awaitPin() async throws -> [Character] {
        try await withCheckedThrowingContinuation { self.continuation = $0 }
    }

    // MARK: - Layout

    private func buildLayout() {
        // Close button — top-right
        view.addSubview(closeButton)
        closeButton.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            closeButton.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            closeButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            closeButton.widthAnchor.constraint(equalToConstant: 44),
            closeButton.heightAnchor.constraint(equalToConstant: 44),
        ])

        // Title / subtitle / dots — stacked vertically above the keypad
        let headerStack = UIStackView(arrangedSubviews: [titleLabel, subtitleLabel, dotStack])
        headerStack.axis      = .vertical
        headerStack.spacing   = 12
        headerStack.alignment = .center

        // Keypad
        let keypadView = buildKeypad()

        let mainStack = UIStackView(arrangedSubviews: [headerStack, keypadView, cancelButton])
        mainStack.axis      = .vertical
        mainStack.spacing   = 40
        mainStack.alignment = .center

        view.addSubview(mainStack)
        mainStack.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            mainStack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            mainStack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }

    private func buildKeypad() -> UIView {
        // 3 × 4 grid: 1-9, (backspace), 0, (confirm)
        let keys: [[KeySpec]] = [
            [.digit("1"), .digit("2"), .digit("3")],
            [.digit("4"), .digit("5"), .digit("6")],
            [.digit("7"), .digit("8"), .digit("9")],
            [.backspace,  .digit("0"), .confirm   ],
        ]

        let rows = UIStackView()
        rows.axis    = .vertical
        rows.spacing = Self.keyGap

        for row in keys {
            let rowStack = UIStackView()
            rowStack.axis         = .horizontal
            rowStack.spacing      = Self.keyGap
            rowStack.distribution = .equalSpacing

            for spec in row {
                let btn = makeKey(spec: spec)
                rowStack.addArrangedSubview(btn)
                NSLayoutConstraint.activate([
                    btn.widthAnchor.constraint(equalToConstant: Self.keySize),
                    btn.heightAnchor.constraint(equalToConstant: Self.keySize),
                ])
            }
            rows.addArrangedSubview(rowStack)
        }

        return rows
    }

    // MARK: - Key factory

    private enum KeySpec { case digit(Character), backspace, confirm }

    private func makeKey(spec: KeySpec) -> UIButton {
        let btn = UIButton(type: .custom)
        btn.backgroundColor = theme.colors.keyBackground

        switch spec {
        case .digit(let c):
            btn.setTitle(String(c), for: .normal)
            btn.setTitleColor(theme.colors.keyText, for: .normal)
            btn.titleLabel?.font = theme.typography.font(size: theme.typography.keySize, weight: .medium)
            btn.addTarget(self, action: #selector(digitPressed(_:)), for: .touchUpInside)
            btn.accessibilityLabel = String(c)

        case .backspace:
            let img = UIImage(systemName: "delete.left")
            btn.setImage(img, for: .normal)
            btn.tintColor = theme.colors.keyText
            btn.addTarget(self, action: #selector(backspacePressed), for: .touchUpInside)
            btn.accessibilityLabel = "Delete"

        case .confirm:
            let img = UIImage(systemName: "checkmark")
            btn.setImage(img, for: .normal)
            btn.tintColor       = .white
            btn.backgroundColor = theme.colors.primary
            btn.alpha           = 0.4
            btn.isEnabled       = false
            btn.addTarget(self, action: #selector(confirmPressed), for: .touchUpInside)
            btn.accessibilityLabel = "Confirm"
            btn.tag = 99 // sentinel for confirm button lookup
        }

        applyKeyShape(btn)
        return btn
    }

    private func applyKeyShape(_ btn: UIButton) {
        switch theme.shape.keyShape {
        case .circle:
            btn.layer.cornerRadius = Self.keySize / 2
        case .rounded:
            btn.layer.cornerRadius = theme.shape.cornerRadius
        case .square:
            btn.layer.cornerRadius = 0
        }
        btn.clipsToBounds = true
    }

    // MARK: - Dot helpers

    private func makeDot(filled: Bool) -> UIView {
        let v = UIView()
        v.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            v.widthAnchor.constraint(equalToConstant:  Self.dotSize),
            v.heightAnchor.constraint(equalToConstant: Self.dotSize),
        ])
        v.layer.cornerRadius = Self.dotSize / 2
        v.backgroundColor    = filled ? theme.colors.dotFilled : theme.colors.dotEmpty
        return v
    }

    private func refreshDots() {
        for (i, view) in dotStack.arrangedSubviews.enumerated() {
            UIView.animate(withDuration: 0.1) {
                view.backgroundColor = i < self.digits.count
                    ? self.theme.colors.dotFilled
                    : self.theme.colors.dotEmpty
            }
        }
    }

    // MARK: - Confirm button state

    private func confirmButton() -> UIButton? {
        // Walk the view hierarchy to find the confirm button by tag
        func find(in v: UIView) -> UIButton? {
            if let b = v as? UIButton, b.tag == 99 { return b }
            for sub in v.subviews { if let b = find(in: sub) { return b } }
            return nil
        }
        return find(in: view)
    }

    private func refreshConfirm() {
        let enabled = digits.count >= Self.minLength
        if let btn = confirmButton() {
            btn.isEnabled = enabled
            UIView.animate(withDuration: 0.15) { btn.alpha = enabled ? 1.0 : 0.4 }
        }
    }

    // MARK: - Actions

    @objc private func digitPressed(_ sender: UIButton) {
        guard let title = sender.title(for: .normal),
              let digit = title.first,
              digits.count < Self.maxLength else { return }
        digits.append(digit)
        refreshDots()
        refreshConfirm()

        // Auto-confirm at max length
        if digits.count == Self.maxLength { confirmPressed() }
    }

    @objc private func backspacePressed() {
        guard !digits.isEmpty else { return }
        digits.removeLast()
        refreshDots()
        refreshConfirm()
    }

    @objc private func confirmPressed() {
        guard digits.count >= Self.minLength, let cont = continuation else { return }
        continuation = nil
        cont.resume(returning: digits)
    }

    @objc private func cancelTapped() {
        guard let cont = continuation else { return }
        continuation = nil
        zeroClear()
        cont.resume(throwing: HashamMobileError.invalidPin("Cancelled"))
    }

    private func zeroClear() {
        for i in 0..<digits.count { digits[i] = "0" }
        digits.removeAll()
    }
}
