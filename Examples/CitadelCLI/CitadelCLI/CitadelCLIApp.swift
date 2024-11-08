//
//  CitadelCLIApp.swift
//  CitadelCLI
//
//  Created by Joannis Orlandos on 06/11/2024.
//

import SwiftUI
import NIOCore
import Citadel
import SwiftTerm

@main
struct CitadelCLIApp: App {
    var body: some Scene {
        WindowGroup {
            SSHView()
                .frame(width: 500, height: 500)
        }
    }
}

struct SSHView: View {
    @State var client: SSHClient?

    var body: some View {
        if let client {
            Terminal(client: client)
        } else {
            ProgressView().task {
                self.client = try! await SSHClient
                    .connect(
                        host: "127.0.0.1",
                        port: 2222,
                        authenticationMethod: .passwordBased(username: "ubuntu", password: "test"),
                        hostKeyValidator: .acceptAnything(),
                        reconnect: .never
                    )
            }
        }
    }
}

struct Terminal: NSViewRepresentable {
    let client: SSHClient

    enum Event {
        case send(ByteBuffer)
        case changeSize(cols: Int, rows: Int)
    }

    final class Coordinator: TerminalViewDelegate {
        let client: SSHClient
        weak var terminalView: TerminalView!
        private let events = AsyncStream<Event>.makeStream()

        init(client: SSHClient) {
            self.client = client
        }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            guard newCols > 0, newRows > 0 else {
                return
            }

            events.continuation.yield(.changeSize(cols: newCols, rows: newRows))
        }

        func setTerminalTitle(source: TerminalView, title: String) {
            
        }

        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {

        }

        func send(source: TerminalView, data: ArraySlice<UInt8>) {
            events.continuation.yield(.send(ByteBuffer(bytes: data)))
        }

        func scrolled(source: TerminalView, position: Double) {

        }

        func clipboardCopy(source: TerminalView, content: Data) {

        }

        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {

        }

        func run() async throws {
            try await client.withPTY(
                .init(
                    wantReply: true,
                    term: "",
                    terminalCharacterWidth: 0,
                    terminalRowHeight: 0,
                    terminalPixelWidth: 0,
                    terminalPixelHeight: 0,
                    terminalModes: .init([.ECHO: 5])
                )
            ) { [events = events.stream] inbound, outbound in
                await withThrowingTaskGroup(of: Void.self) { taskGroup in
                    taskGroup.addTask {
                        for try await input in inbound {
                            switch input {
                            case .stdout(var buffer), .stderr(var buffer):
                                let bytes = buffer.readBytes(length: buffer.readableBytes)![...]
                                await self.terminalView!.feed(byteArray: bytes)
                            }
                        }
                    }

                    taskGroup.addTask {
                        for try await event in events {
                            switch event {
                            case .send(let buffer):
                                try await outbound.write(buffer)
                            case .changeSize(let cols, let rows):
                                try await outbound.changeSize(cols: cols, rows: rows)
                            }
                        }
                    }
                }
            }
        }
    }

    func makeNSView(context: Context) -> TerminalView {
        let terminalView = TerminalView()
        terminalView.terminalDelegate = context.coordinator
        context.coordinator.terminalView = terminalView

        Task {
            try await context.coordinator.run()
        }

        return terminalView
    }

    func updateNSView(_ nsView: TerminalView, context: Context) {

    }

    func makeCoordinator() -> Coordinator {
        Coordinator(client: client)
    }
}
