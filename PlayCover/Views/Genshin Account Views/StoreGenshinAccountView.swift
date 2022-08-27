//
//  StoreGenshinAccountView.swift
//  PlayCover
//
//  Created by José Elias Moreno villegas on 21/07/22.
//

import SwiftUI

struct StoreGenshinAccountView: View {
    @Environment(\.presentationMode) var presentationMode
    @State var folderName = ""
    @State var selectedRegion = ""
    @State var regionIsNotValid = false
    var body: some View {
        VStack(alignment: .center, spacing: 16) {
            Spacer()
            Text("storeAccount.storeAcc").font(.largeTitle).lineLimit(1).fixedSize()
            Spacer()
            HStack(spacing: 0) {
                Picker(
                    selection: $selectedRegion,
                    label: Text("storeAccount.selectAccRegion")
                        .font(.headline).lineLimit(1).fixedSize(),
                    content: {
                        Text("storeAccount.selectAccRegion.usa").tag("os_usa")
                        Text("storeAccount.selectAccRegion.euro").tag("os_euro")
                        Text("storeAccount.selectAccRegion.asia").tag("os_asia")
                        Text("storeAccount.selectAccRegion.cht").tag("os_cht")
                    }).pickerStyle(.segmented)
                Spacer()
            }
            HStack {
                Text("storeAccount.nameOfAcc")
                    .font(.headline).lineLimit(1).fixedSize()
                TextField(NSLocalizedString(
                    "storeAccount.nameOfAcc.textfieldPlaceholder", comment: ""), text: $folderName)
            }
            Spacer()
            HStack {
                Button(action: {
                    if !folderName.isEmpty && !selectedRegion.isEmpty {
                        do {
                            if try checkCurrentRegion(selectedRegion: selectedRegion) {
                                regionIsNotValid = false
                                storeUserData(folderName: folderName.lowercased(), accountRegion: selectedRegion)
                                presentationMode.wrappedValue.dismiss()
                            } else {
                                regionIsNotValid = true
                            }
                        } catch {
                            Log.shared.error(
                                "An error occoured while trying to store your account: " + error.localizedDescription)
                        }
                    } else { presentationMode.wrappedValue.dismiss() }
                }, label: {
                    Text("storeAccount.store").frame(minWidth: 300, alignment: .center)
                }).controlSize(.large).font(.title3).padding()
                    .keyboardShortcut(.defaultAction)
                    .disabled(selectedRegion == "" || folderName == "")

                Button(action: {
                    presentationMode.wrappedValue.dismiss()
                }, label: {
                    Text("button.Close").frame(alignment: .center)
                })
                .controlSize(.large).padding()
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding()
        .alert(NSLocalizedString("alert.storeAccount.regionIsNotValid", comment: ""), isPresented: $regionIsNotValid) {
            Button("button.Close", role: .cancel) {
                regionIsNotValid.toggle()
                presentationMode.wrappedValue.dismiss()
            }
        }
    }
}

struct GenshinView_preview: PreviewProvider {
    static var previews: some View {
        StoreGenshinAccountView()
    }
}
