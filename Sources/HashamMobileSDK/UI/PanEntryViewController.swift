import UIKit

/// Full-screen PAN entry overlay for physical cards.
///
/// Receives a masked PAN (e.g. "4111 **** **** 1234"), displays it, and shows a numeric
/// keypad for the cardholder to enter the hidden positions. Returns the reconstructed full
/// PAN via `awaitPan()`. The host app never sees individual keystrokes.
internal final class PanEntryViewController: UIViewController {

    private static let keySize: CGFloat = 72
    private static let keyGap:  CGFloat = 16

    private let maskedPan:    String
    private let theme:        PinTheme

    private var panChars:     [Character?]
    private var hiddenIndices: [Int]
    private var entered:      [Character] = []

    private var continuation:   CheckedContinuation<String, Error>?
    private var inputBoxes:     [UILabel]  = []
    private weak var confirmBtn: UIButton?

    // MARK: - Init

    init(maskedPan: String, theme: PinTheme) {
        self.maskedPan = maskedPan
        self.theme     = theme

        let stripped  = maskedPan.replacingOccurrences(of: " ", with: "")
        panChars      = stripped.map { $0 == "*" ? nil : $0 }
        hiddenIndices = panChars.indices.filter { panChars[$0] == nil }

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
        guard let cont = continuation else { return }
        continuation = nil
        zeroClear()
        cont.resume(throwing: HashamMobileError.invalidPin("Cancelled"))
    }

    // MARK: - Awaitable entry point

    func awaitPan() async throws -> String {
        try await withCheckedThrowingContinuation { self.continuation = $0 }
    }

    // MARK: - Layout

    private func buildLayout() {
        // Close button (top-right)
        let closeButton = UIButton(type: .system)
        closeButton.setImage(UIImage(systemName: "xmark"), for: .normal)
        closeButton.tintColor = theme.colors.subtitleColor
        closeButton.addTarget(self, action: #selector(closeTapped), for: .touchUpInside)
        view.addSubview(closeButton)
        closeButton.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            closeButton.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            closeButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            closeButton.widthAnchor.constraint(equalToConstant: 44),
            closeButton.heightAnchor.constraint(equalToConstant: 44),
        ])

        // Title
        let titleLabel = UILabel()
        titleLabel.text          = "Verify your card"
        titleLabel.textColor     = theme.colors.titleColor
        titleLabel.font          = theme.typography.font(size: theme.typography.titleSize, weight: .semibold)
        titleLabel.textAlignment = .center

        // Masked PAN display
        let maskedLabel = UILabel()
        maskedLabel.text          = maskedPan.replacingOccurrences(of: "*", with: "•")
        maskedLabel.textColor     = theme.colors.subtitleColor
        maskedLabel.font          = theme.typography.font(size: 18)
        maskedLabel.textAlignment = .center

        // Instruction
        let instructionLabel = UILabel()
        instructionLabel.text          = "Enter the \(hiddenIndices.count) hidden digits"
        instructionLabel.textColor     = theme.colors.subtitleColor
        instructionLabel.font          = theme.typography.font(size: theme.typography.subtitleSize)
        instructionLabel.textAlignment = .center

        // Input boxes
        let boxRow = buildInputBoxRow()

        // Header stack
        let header = UIStackView(arrangedSubviews: [titleLabel, maskedLabel, instructionLabel, boxRow])
        header.axis      = .vertical
        header.spacing   = 10
        header.alignment = .center

        // Keypad
        let keypad = buildKeypad()

        // Cancel button (bottom)
        let cancelButton = UIButton(type: .system)
        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.setTitleColor(theme.colors.subtitleColor, for: .normal)
        cancelButton.titleLabel?.font = theme.typography.font(size: 15)
        cancelButton.addTarget(self, action: #selector(closeTapped), for: .touchUpInside)

        let main = UIStackView(arrangedSubviews: [header, keypad, cancelButton])
        main.axis      = .vertical
        main.spacing   = 32
        main.alignment = .center

        view.addSubview(main)
        main.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            main.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            main.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }

    private func buildInputBoxRow() -> UIStackView {
        inputBoxes.removeAll()
        let row = UIStackView()
        row.axis    = .horizontal
        row.spacing = 8
        for _ in 0..<hiddenIndices.count {
            let lbl = UILabel()
            lbl.text          = "_"
            lbl.textColor     = theme.colors.subtitleColor
            lbl.font          = theme.typography.font(size: 20, weight: .medium)
            lbl.textAlignment = .center
            lbl.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                lbl.widthAnchor.constraint(equalToConstant: 32),
                lbl.heightAnchor.constraint(equalToConstant: 40),
            ])
            lbl.layer.borderColor  = theme.colors.dotEmpty.cgColor
            lbl.layer.borderWidth  = 1
            lbl.layer.cornerRadius = 4
            inputBoxes.append(lbl)
            row.addArrangedSubview(lbl)
        }
        return row
    }

    private func buildKeypad() -> UIView {
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
        case .backspace:
            btn.setImage(UIImage(systemName: "delete.left"), for: .normal)
            btn.tintColor = theme.colors.keyText
            btn.addTarget(self, action: #selector(backspacePressed), for: .touchUpInside)
        case .confirm:
            btn.setImage(UIImage(systemName: "checkmark"), for: .normal)
            btn.tintColor       = .white
            btn.backgroundColor = theme.colors.primary
            btn.alpha           = 0.4
            btn.isEnabled       = false
            btn.addTarget(self, action: #selector(confirmPressed), for: .touchUpInside)
            self.confirmBtn = btn
        }
        switch theme.shape.keyShape {
        case .circle:  btn.layer.cornerRadius = Self.keySize / 2
        case .rounded: btn.layer.cornerRadius = theme.shape.cornerRadius
        case .square:  btn.layer.cornerRadius = 0
        }
        btn.clipsToBounds = true
        return btn
    }

    // MARK: - Input handling

    @objc private func digitPressed(_ sender: UIButton) {
        guard let title = sender.title(for: .normal),
              let digit = title.first,
              entered.count < hiddenIndices.count else { return }
        entered.append(digit)
        refreshBoxes()
        if entered.count == hiddenIndices.count { confirmPressed() }
    }

    @objc private func backspacePressed() {
        guard !entered.isEmpty else { return }
        entered.removeLast()
        refreshBoxes()
    }

    @objc private func confirmPressed() {
        guard entered.count >= hiddenIndices.count, let cont = continuation else { return }
        continuation = nil
        let pan = reconstructPan()
        zeroClear()
        cont.resume(returning: pan)
    }

    @objc private func closeTapped() {
        guard let cont = continuation else { return }
        continuation = nil
        zeroClear()
        cont.resume(throwing: HashamMobileError.invalidPin("Cancelled"))
        dismiss(animated: true)
    }

    // MARK: - Helpers

    private func refreshBoxes() {
        for (i, lbl) in inputBoxes.enumerated() {
            if i < entered.count {
                lbl.text      = String(entered[i])
                lbl.textColor = theme.colors.keyText
            } else {
                lbl.text      = "_"
                lbl.textColor = theme.colors.subtitleColor
            }
        }
        let allFilled = entered.count >= hiddenIndices.count
        if let btn = confirmBtn {
            btn.isEnabled = allFilled
            UIView.animate(withDuration: 0.15) { btn.alpha = allFilled ? 1.0 : 0.4 }
        }
    }

    private func reconstructPan() -> String {
        var result = panChars
        for (slot, panIdx) in hiddenIndices.enumerated() {
            result[panIdx] = entered[slot]
        }
        return result.map { String($0!) }.joined()
    }

    private func zeroClear() {
        for i in 0..<entered.count { entered[i] = "0" }
        entered.removeAll()
    }
}
