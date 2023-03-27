#ifndef NCDIALOG_H
#define NCDIALOG_H

#include <QDialog>
#include "pcap.h"
#include <iostream>
#include <QAbstractButton>
using namespace std;

namespace Ui {
class NcDialog;
}

class NcDialog : public QDialog
{
    Q_OBJECT

public:
    explicit NcDialog(QWidget *parent = nullptr);
    ~NcDialog();
protected:
    void showEvent(QShowEvent *event) override;

private slots:
    void on_buttonBox_clicked(QAbstractButton *button);
signals:
    void sendSDev(QString);

private:
    Ui::NcDialog *ui;
};

#endif // NCDIALOG_H
