// QRWebcamScanner.swift (Mac)
// Lit le QR code de secours affiché par l'iPhone avec la caméra du Mac (J1 §3.8, quand le réseau ne passe pas).
// Moindre privilège : caméra allumée UNIQUEMENT pendant ce scan ; aucune image n'est conservée.
// (AVCaptureMetadataOutput n'existe pas sur macOS : on analyse les images avec CIDetector.)

import SwiftUI
import AVFoundation
import CoreImage

struct QRWebcamScanner: NSViewRepresentable {
    let onCode: (String) -> Void

    func makeNSView(context: Context) -> ScannerNSView {
        let view = ScannerNSView()
        view.onCode = onCode
        view.start()
        return view
    }

    func updateNSView(_ nsView: ScannerNSView, context: Context) {}

    static func dismantleNSView(_ nsView: ScannerNSView, coordinator: ()) { nsView.stop() }
}

final class ScannerNSView: NSView, AVCaptureVideoDataOutputSampleBufferDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "robair.webcam")
    private let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
    private var delivered = false

    func start() {
        wantsLayer = true
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            DispatchQueue.main.async { if granted { self?.configure() } }
        }
    }

    func stop() {
        let session = self.session
        queue.async { if session.isRunning { session.stopRunning() } }   // caméra coupée dès la fermeture
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureVideoDataOutput()
        output.setSampleBufferDelegate(self, queue: queue)
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = bounds
        preview.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        layer?.addSublayer(preview)
        let session = self.session
        queue.async { session.startRunning() }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !delivered, let pixels = CMSampleBufferGetImageBuffer(sampleBuffer),
              let feature = detector?.features(in: CIImage(cvPixelBuffer: pixels)).first as? CIQRCodeFeature,
              let text = feature.messageString, text.utf8.count <= 1500 else { return }
        delivered = true
        stop()
        DispatchQueue.main.async { self.onCode?(text) }
    }
}
